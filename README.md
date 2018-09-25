# L1TF (Foreshadow) VM guest to host memory read PoC

This is a PoC for CVE-2018-3646. This is a vulnerability that enables malicious/compromised VM guests to read host machine physical memory.

The vulnerability is exploitable on most Intel CPUs that support VT-x and EPT (extended page tables). This includes all Intel Core iX CPUs. This PoC works only on 64 bit x86-64 systems (host and guest).

At present, the mitigation for this vulnerability is supposed to be accomplished by the VMM. Therefore a patched host system does not offer protection from compromised guest VMs if the VMM is not up to date.

The setup on which this PoC was tested:

    CPU: Intel Core i7-6500U
    Host system: Ubuntu 18.04.1, kernel: Ubuntu kernel 4.15.0-34 from Aug 27 (has patch for L1TF) 
    VMM: VMware Workstation player 14.1.2 build-8497320 (one version prior to the newest patched version)
    Guest system: Same as host

VMware has released a patch, available since version 14.1.3 of VMware Workstation player. All VMware products received a similar patch on August 14 2018. It is reasonable to assume that this PoC will reproduce on all other VMware products last patched prior to that date (including ESX).

Needless to say, this PoC is likely to reproduce on all other modern (non VMware) VMMs last patched prior to that date. This includes VirtualBox, KVM, etc. I did not attempt to test against these yet.

# How this PoC works

Given root access to a guest VM, the PoC uses /dev/mem in order to:
 1) Map a page to a dummy (magic) physical address
 2) Exhaustively search the entire memory (of the guest VM) in order to find the PTE that maps the magic address
 3) Rewrite the magic address PTE with a special (L1TF) entry for the target *host* physical address marked as *not-present*
 
All of the above is done in order to perform the attack with userspace code only. A kernel module loaded into the compromised guest kernel could do the above steps instantly.

At that point the PoC will run code that speculatively accesses the "not present" page and leaks the acquired information via a cache timing side channel (as described in the L1TF writeups).

# Reproducing on guest Kernels with CONFIG_STRICT_DEVMEM enabled

As of late, this is on by default in most kernel configs. This prevents /dev/mem from being useful. For this case, a kernel module "devmem_allow" is included with this PoC.

As the guest machine is considered compromised, loading a kernel module is within the scope of this PoC.

This kernel module simply patches out the "devmem_is_allowed" function from the running kernel, re-enabling /dev/mem to be used as before. Usage (as root):

    apt-get install build-essential linux-headers-$(uname -r)
    cd devmem_allow_ko
    make
    insmod devmem_allow.ko
    
DO NOT use this on your host kernel! This is intended to be loaded into the guest kernel (that you don't care to crash if something goes sideways).

# Using the PoC

Log in as root to the guest machine. Build the code using:

    ./build.sh
    
To run it, as root:
    
    ./doit <host physical address> <length>
    
This will dump out the contents at the given host physical address *ASSUMING the data is being held in the L1 cache!* 
The L1 cache is shared between VMs and host processes *if they run on the same CPU core*. Therefore, if the VM is limited to fewer cores than are available on a host machine, some luck (or time) is required before the targeted process ends up on the same core as the VM. This PoC attempts running on all available cores.

As an example, on the *host* machine, we'll cheat in order get the (randomized) physical address of the kernels "sys_call_table":

    $ sudo cat /proc/kallsyms | grep _stext
    ffffffff84800000 T _stext

    $ sudo cat /proc/kallsyms | grep sys_call_table
    ffffffff856001a0 R sys_call_table

    $ sudo cat /proc/iomem | grep 'Kernel code'    
    2fe600000-2ff2031d0 : Kernel code

To get the physical address, the calculation is:

    0xffffffff856001a0 - 0xffffffff84800000 + 0x2fe600000 = 0x2ff4001a0
    
Having the physical address, we can now read it using the PoC on the *guest* machine:

    sudo ./doit 0x2ff4001a0 0x40

    Looking for the PTE for VA 0x7fd339106000 in RAM...
    Our PTE now mapped. Value: 7badbee235
    Dumping from VA 0x7fd3391061a0

    70 72 a7 84 ff ff ff ff 30 73 a7 84 ff ff ff ff
    00 45 a7 84 ff ff ff ff 30 20 a7 84 ff ff ff ff
    70 c9 a7 84 ff ff ff ff a0 c9 a7 84 ff ff ff ff
    80 c9 a7 84 ff ff ff ff e0 fd a8 84 ff ff ff ff

Alternatively, a utility called "phys" is included with this PoC. When run on the host machine, it forces some datda into the L1 cache on a single core, and outputs a physical address of this data. This address can be used with the PoC on the guest VM.

# Practicality

The attack is limited by the following factors:
 1) Data needs to be in the L1 cache (only 32KB) in order to be read at the time of sampling one byte. For every byte.
 2) Each CPU core has a separate L1 cache (shared between the 2 hyperthreads). The attacker process must run on the right core.
 3) Physical address randomization makes it harder for the attacker to find the targeted data.
 
The limitaion of host physical address randomization appears to not be very significant for this attack vector, as on my machine I got about 14 bits of entropy for the host kernels physical addresses. Therefore, it's possible to find the very recognizable sys_call_table with 16k read attempts (perhaps 10-20 minutes based on this PoC). From there all addresses in the host kernel can be resolved.

As for the other limitations, the attacker will be limited to reading "hot" (very frequently accessed) data. For example, the kernel routing table (exposing host IPs), hard disk ecryption key (if in RAM), etc. However, if the attacker has some interface to quickly trigger a data access on the victim process (for example, HTTP request, IP packet, etc), this data will effectively become "hot" if the request is sent repeatedly. An example for such data is authentication tokens (comparison with a hash means the correct hash is accessed in memory).

# Implications

It is not safe to run VMs (with isolation in mind) on unpatched VMMs on vulnerable CPUs.
If a VM on an unpatched ESX server (or other virtualisation setup) is compromised, all data on all other guest VMs and the host may be read.

A specific interesting case is the use of VMs for strong internet anonymity. The user runs a browser (or hidden service) in an isolated guest VM. The VM is accessible only to a virtual network interface that can only route traffic over TOR. The assumption is that even if the guest VM is compromised, the attacker will not be able to know the real host machines IP address (or other identifying information). Using this attack, it is however easy to read the hosts routing table to extract such information.

Therefore in all such use cases, users *must* ensure that *both* their host kernel and VMM are patched, the corresponding CPU microcode update has been applied by the host kernel, *and* that the VMs do not share hyperthreads with any other processes.
