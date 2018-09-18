# L1TF (Foreshadow) VM guest to host memory read PoC

This is a PoC for CVE-2018-3646. This is a vulnerability that enables malicious/compromised VM guests to read host machine physical memory.

The vulnerability is exploitable on most Intel CPUs that support VT-x and EPT (extended page tables). This includes all Intel Core iX CPUs.

At present, the mitigation for this vulnerability is supposed to be accomplished by the VMM. Therefore a patched host system does not offer protection from compromised guest VMs if the VMM is not up to date.

The setup on which this PoC was tested:

CPU: Intel Core i7-6500U
Host system: Ubuntu 18.04.1, kernel: Ubuntu kernel 4.15.0-34 from Aug 27 (has patch for L1TF) 

VMM: VMware Workstation player 14.1.2 build-8497320 (one version prior to the newest patched version)

Guest system: Same as host


VMWare has released a patch, available since version 14.1.3 of VMware Workstation player. All VMware products received a similar patch on August 14 2018. It is reasonable to assume that this PoC will reproduce on all other VMware products last patched prior to that date (including ESX).

