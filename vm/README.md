Example configuration for libvirt. <br> <br>

I used a Win 10 VM, build 19044. <br>
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

## For older versions of libvirt

Some versions of libvirt may not use the ```-object``` syntax for the RAM, instead they will only allocate the RAM amount using ```-m``` flag, that is a deprecated way. <br>
In this case, you can solve the problem by manually adding the file-backed RAM object, and by setting a NUMA object that will make the actual RAM fall to the other object, linking them using the id:

```
  <commandline xmlns="http://libvirt.org/schemas/domain/qemu/1.0">
    <arg value='-object'/>
    <arg value='memory-backend-file,id=pc.ram,size=2147483648,mem-path=/dev/shm/qemu-ram/win10,share=on'/>
    <arg value='-numa'/>
    <arg value='node,memdev=pc.ram'/>
  </commandline>
```

You have to add this at the very end of the domain.

## Error troubleshooting

### Permission denied error with AppArmor
Modify ```/etc/apparmor.d/abstractions/libvirt-qemu```, for example with:

```
/dev/shm/* rw
```

or with some stricter rules.

### Kernel debug errors when virtualizing Windows with QEMU-KVM
Disable Hyper-V enlightments in features and in clocks. <br>
Install the Windows Debugging tools from the SDK even on the target machine. <br>
Make sure that the host and the target computer can connect to each other and that there aren't any conflicting firewall rules. <br>
Make sure that the registry in the proper state:

```
> bcdedit /bootdebug {bootmgr} on
> bcdedit /debug on
> bcdedit /bootdebug on
> bcdedit /set nointegritychecks on
> bcdedit /set testsigning on
```

For more information: [this](https://bugzilla.redhat.com/show_bug.cgi?format=multiple&id=1947015) and [this](http://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html).

### If you can't get it right with libvirt
Then use [qemu without libvirt](https://developers.redhat.com/blog/2020/03/06/configure-and-run-a-qemu-based-vm-outside-of-libvirt#create_a_boot_script_from_the_qemu_command).
