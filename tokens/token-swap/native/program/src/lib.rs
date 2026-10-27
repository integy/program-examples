// ============================================================================
// solana-foundation/program-examples Issue #755
// tokens/token-swap: Add Native (Solana Native) flavor without Anchor
// Target Path: tokens/token-swap/native/program/src/lib.rs
// ============================================================================

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
};
use spl_token::state::Account as SplAccount;

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq)]
pub enum SwapInstruction {
    CreateAmm { id: [u8; 32], fee: u16 },
    CreatePool,
    Swap {
        swap_a: bool,
        input_amount: u64,
        min_output_amount: u64,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Default, PartialEq)]
pub struct Amm {
    pub admin: Pubkey,
    pub id: [u8; 32],
    pub fee: u16,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Default, PartialEq)]
pub struct Pool {
    pub amm: Pubkey,
    pub mint_a: Pubkey,
    pub mint_b: Pubkey,
    pub vault_a: Pubkey,
    pub vault_b: Pubkey,
    pub lp_mint: Pubkey,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = SwapInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        SwapInstruction::CreateAmm { id, fee } => {
            msg!("Instruction: CreateAmm");
            process_create_amm(program_id, accounts, id, fee)
        }
        SwapInstruction::CreatePool => {
            msg!("Instruction: CreatePool");
            process_create_pool(program_id, accounts)
        }
        SwapInstruction::Swap {
            swap_a,
            input_amount,
            min_output_amount,
        } => {
            msg!("Instruction: Swap");
            process_swap(program_id, accounts, swap_a, input_amount, min_output_amount)
        }
    }
}

fn process_create_amm(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    id: [u8; 32],
    fee: u16,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;
    let amm_account = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_amm, _) = Pubkey::find_program_address(&[b"amm", &id], program_id);
    if expected_amm != *amm_account.key {
        return Err(ProgramError::InvalidSeeds);
    }

    let amm_state = Amm {
        admin: *payer.key,
        id,
        fee,
    };
    amm_state.serialize(&mut *amm_account.data.borrow_mut())?;
    Ok(())
}

fn process_create_pool(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let _payer = next_account_info(account_iter)?;
    let amm_account = next_account_info(account_iter)?;
    let pool_account = next_account_info(account_iter)?;
    let _authority = next_account_info(account_iter)?;
    let mint_a = next_account_info(account_iter)?;
    let mint_b = next_account_info(account_iter)?;
    let vault_a = next_account_info(account_iter)?;
    let vault_b = next_account_info(account_iter)?;
    let lp_mint = next_account_info(account_iter)?;

    let pool_state = Pool {
        amm: *amm_account.key,
        mint_a: *mint_a.key,
        mint_b: *mint_b.key,
        vault_a: *vault_a.key,
        vault_b: *vault_b.key,
        lp_mint: *lp_mint.key,
    };
    pool_state.serialize(&mut *pool_account.data.borrow_mut())?;
    Ok(())
}

fn process_swap(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _swap_a: bool,
    input_amount: u64,
    min_output_amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let trader = next_account_info(account_iter)?;
    let _amm_account = next_account_info(account_iter)?;
    let _pool_account = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    let trader_source = next_account_info(account_iter)?;
    let vault_source = next_account_info(account_iter)?;
    let vault_destination = next_account_info(account_iter)?;
    let trader_destination = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;

    if !trader.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let source_account = SplAccount::unpack(&vault_source.data.borrow())?;
    let dest_account = SplAccount::unpack(&vault_destination.data.borrow())?;

    let reserve_in = source_account.amount;
    let reserve_out = dest_account.amount;

    if reserve_in == 0 || reserve_out == 0 {
        return Err(ProgramError::InsufficientFunds);
    }

    let output_amount = (reserve_out as u128)
        .checked_mul(input_amount as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div((reserve_in as u128).checked_add(input_amount as u128).ok_or(ProgramError::ArithmeticOverflow)?)
        .ok_or(ProgramError::ArithmeticOverflow)? as u64;

    if output_amount < min_output_amount {
        msg!("Slippage tolerance exceeded: expected >= {}, got {}", min_output_amount, output_amount);
        return Err(ProgramError::Custom(1));
    }

    let transfer_in_ix = spl_token::instruction::transfer(
        token_program.key,
        trader_source.key,
        vault_source.key,
        trader.key,
        &[],
        input_amount,
    )?;
    invoke(
        &transfer_in_ix,
        &[trader_source.clone(), vault_source.clone(), trader.clone(), token_program.clone()],
    )?;

    let (_authority_pda, bump) = Pubkey::find_program_address(&[b"authority"], program_id);
    let authority_seeds: &[&[u8]] = &[b"authority", &[bump]];

    let transfer_out_ix = spl_token::instruction::transfer(
        token_program.key,
        vault_destination.key,
        trader_destination.key,
        authority.key,
        &[],
        output_amount,
    )?;
    invoke_signed(
        &transfer_out_ix,
        &[vault_destination.clone(), trader_destination.clone(), authority.clone(), token_program.clone()],
        &[authority_seeds],
    )?;

    msg!("Swap completed successfully: {} in -> {} out", input_amount, output_amount);
    Ok(())
}
