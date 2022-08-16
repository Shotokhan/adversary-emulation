Example configuration for libvirt. <br> <br>

I used a Win 10 VM, build 19041. <br>
This configuration was obtained using gnome-boxes, then it was changed by hand using libvirt's interface for sanity checking. <br>
To emulate arbitrary read&write from a compromised hypervisor, you need to have a file-backed RAM, which can be obtained with this configuration:

```
  <memoryBacking>
    <source type='file'/>
    <access mode='shared'/>
  </memoryBacking>
```
 
At this point, the RAM is backed on a sub-folder of ```$HOME/.config/libvirt/qemu/ram```. <br>
To make the file memory-backed, i.e. to have a file-backed RAM for VM which goes on physical RAM instead of disk, you have to set the ```ram``` sub-folder as a symbolic link to ```/dev/shm```. <br> <br>
Another thing to do, if you want to do kernel debug with KDNET, is to change the network interface's model type:

```
    <interface type='bridge'>
      <mac address='52:54:00:d8:2c:91'/>
      <source bridge='virbr0'/>
      <target dev='tap0'/>
      <model type='e1000'/>
      <address type='pci' domain='0x0000' bus='0x07' slot='0x01' function='0x0'/>
    </interface>
```

I just added the ```<model type='e1000'/>``` line. <br>
This is the configuration for libvirt, which uses QEMU and KVM. There should be similar configurations for other providers, like VMWare and VirtualBox.

