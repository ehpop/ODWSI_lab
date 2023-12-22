import ctr_sp
import ctr_mp

if __name__ == "__main__":
    print("Single process:")
    times_encryption, times_decryption = ctr_sp.compare_times_for_sizes()
    ctr_sp.print_results(times_encryption, times_decryption)

    print(30 * "-")

    print("Multi process:")
    times_encryption, times_decryption = ctr_mp.compare_times_for_sizes()
    ctr_mp.print_results(times_encryption, times_decryption)
