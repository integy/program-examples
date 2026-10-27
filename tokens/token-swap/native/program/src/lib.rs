// ============================================================================
// solana-foundation/program-examples Issue #755 (Patched & Hardened)
// tokens/token-swap: Native (Solana Native) AMM Program
// Target Path: tokens/token-swap/native/program/src/lib.rs
//
// Hygiene & Security Fixes Applied:
// 1. [Security P0]: Validates vault_source and vault_destination against Pool state.
// 2. [Security P1]: Allocates & funds PDA for Amm using invoke_signed with system_instruction::create_account.
// 3. [Security P1]: Prevents pool overwrites by verifying pool_account is uninitialized.
// 4. [Logic P1]: Applies Amm.fee (basis points) to input_amount before constant-product reserve calculation.
// 5. [Build P1]: Accompanied by tokens/token-swap/native/program/Cargo.toml.
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
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use spl_token::state::Account as SplAccount;

pub const FEE_DENOMINATOR: u64 = 10_000; // Basis points (100% = 10,000 bps)

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
    pub is_initialized: bool,
    pub admin: Pubkey,
    pub id: [u8; 32],
    pub fee: u16,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Default, PartialEq)]
pub struct Pool {
    pub is_initialized: bool,
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
    let system_program = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_amm, bump) = Pubkey::find_program_address(&[b"amm", &id], program_id);
    if expected_amm != *amm_account.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Allocate PDA if not already created
    if amm_account.data_is_empty() {
        let rent = Rent::get()?;
        let space = 1 + 32 + 32 + 2; // is_initialized (1) + admin (32) + id (32) + fee (2)
        let rent_lamports = rent.minimum_balance(space);

        let create_account_ix = system_instruction::create_account(
            payer.key,
            amm_account.key,
            rent_lamports,
            space as u64,
            program_id,
        );
        let amm_signer_seeds: &[&[u8]] = &[b"amm", &id, &[bump]];
        invoke_signed(
            &create_account_ix,
            &[payer.clone(), amm_account.clone(), system_program.clone()],
            &[amm_signer_seeds],
        )?;
    }

    let mut amm_state = Amm::try_from_slice(&amm_account.data.borrow()).unwrap_or_default();
    if amm_state.is_initialized {
        msg!("Error: AMM is already initialized");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    amm_state.is_initialized = true;
    amm_state.admin = *payer.key;
    amm_state.id = id;
    amm_state.fee = fee;
    amm_state.serialize(&mut *amm_account.data.borrow_mut())?;

    msg!("AMM created successfully with fee {} bps", fee);
    Ok(())
}

fn process_create_pool(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;
    let amm_account = next_account_info(account_iter)?;
    let pool_account = next_account_info(account_iter)?;
    let _authority = next_account_info(account_iter)?;
    let mint_a = next_account_info(account_iter)?;
    let mint_b = next_account_info(account_iter)?;
    let vault_a = next_account_info(account_iter)?;
    let vault_b = next_account_info(account_iter)?;
    let lp_mint = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Check pool is not already initialized
    if !pool_account.data_is_empty() {
        if let Ok(existing) = Pool::try_from_slice(&pool_account.data.borrow()) {
            if existing.is_initialized {
                msg!("Error: Pool account is already initialized");
                return Err(ProgramError::AccountAlreadyInitialized);
            }
        }
    }

    let pool_state = Pool {
        is_initialized: true,
        amm: *amm_account.key,
        mint_a: *mint_a.key,
        mint_b: *mint_b.key,
        vault_a: *vault_a.key,
        vault_b: *vault_b.key,
        lp_mint: *lp_mint.key,
    };
    pool_state.serialize(&mut *pool_account.data.borrow_mut())?;

    msg!("Pool initialized successfully for mints {} and {}", mint_a.key, mint_b.key);
    Ok(())
}

fn process_swap(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    swap_a: bool,
    input_amount: u64,
    min_output_amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let trader = next_account_info(account_iter)?;
    let amm_account = next_account_info(account_iter)?;
    let pool_account = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    let trader_source = next_account_info(account_iter)?;
    let vault_source = next_account_info(account_iter)?;
    let vault_destination = next_account_info(account_iter)?;
    let trader_destination = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;

    if !trader.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify AMM state & fee
    let amm = Amm::try_from_slice(&amm_account.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if !amm.is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }

    // Verify Pool state & link to AMM
    let pool = Pool::try_from_slice(&pool_account.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if !pool.is_initialized || pool.amm != *amm_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // Security Check (P0): Validate that vault accounts match pool definition
    let (expected_vault_src, expected_vault_dst) = if swap_a {
        (pool.vault_a, pool.vault_b)
    } else {
        (pool.vault_b, pool.vault_a)
    };

    if *vault_source.key != expected_vault_src {
        msg!("Error: vault_source does not match pool state");
        return Err(ProgramError::InvalidAccountData);
    }
    if *vault_destination.key != expected_vault_dst {
        msg!("Error: vault_destination does not match pool state");
        return Err(ProgramError::InvalidAccountData);
    }

    // Unpack vault balances
    let source_account = SplAccount::unpack(&vault_source.data.borrow())?;
    let dest_account = SplAccount::unpack(&vault_destination.data.borrow())?;

    let reserve_in = source_account.amount;
    let reserve_out = dest_account.amount;

    if reserve_in == 0 || reserve_out == 0 {
        return Err(ProgramError::InsufficientFunds);
    }

    // Fee-adjusted constant product calculation:
    // effective_input = input_amount * (FEE_DENOMINATOR - fee) / FEE_DENOMINATOR
    let fee_factor = (FEE_DENOMINATOR as u128)
        .checked_sub(amm.fee as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let input_after_fee = (input_amount as u128)
        .checked_mul(fee_factor)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(FEE_DENOMINATOR as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Constant product formula: out = (reserve_out * in_after_fee) / (reserve_in + in_after_fee)
    let output_amount = (reserve_out as u128)
        .checked_mul(input_after_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(
            (reserve_in as u128)
                .checked_add(input_after_fee)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        )
        .ok_or(ProgramError::ArithmeticOverflow)? as u64;

    if output_amount < min_output_amount {
        msg!(
            "Slippage tolerance exceeded: expected >= {}, got {}",
            min_output_amount,
            output_amount
        );
        return Err(ProgramError::Custom(1)); // SlippageExceeded
    }

    // 1. Transfer full input tokens from trader to source vault
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
        &[
            trader_source.clone(),
            vault_source.clone(),
            trader.clone(),
            token_program.clone(),
        ],
    )?;

    // 2. Transfer output tokens from destination vault to trader via PDA authority
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
        &[
            vault_destination.clone(),
            trader_destination.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[authority_seeds],
    )?;

    msg!(
        "Swap completed: {} in (fee: {} bps) -> {} out",
        input_amount,
        amm.fee,
        output_amount
    );
    Ok(())
}
