format ELF64 executable 3 at 10 * 1048576

include 'fastcall_v1.inc'
include 'stdmacros.inc'
include 'stdio.inc'

struct ICMPHDR ty:?, cod:?, _id:?, seq:?
    .type               db ty
    .code               db cod
    .checksum           dw ?
    .union:             dw _id, seq
    virtual at .union
        .echo.id         dw ?
        .echo.sequence   dw ?
    end virtual
    virtual at .union
        .gateway        dd ?
    end virtual
    virtual at .union
        .frag.__unused  dw ?
        .frag.mtu       dw ?
    end virtual
    virtual at .union
        .reserved       rb 4
    end virtual
end struct

struct SOCKADDR_IN af:?
    .sin_family     dw af
    .sin_port       dw ?
    .sin_addr       IN_ADDR
    .sin_zero       rb 8
end struct

struct TIMESPEC s:?, ns:?
    .tv_sec         dq s
    .tv_nsec        dq ns
end struct

struct TIMEVAL s:?, µs:?
    .tv_sec         dq s
    .tv_usec        dq µs
end struct

struct IN_ADDR
    .s_addr         dd ?
end struct

struct HOSTENT
    .h_name         dq ?
    .h_aliases      dq ?
    .h_addrtype     dd ?
    .h_length       dd ?
    .h_addr_list    dq ?
end struct

            FLAG_STOP           = 00000001b
            FLAG_OPEN_SOCKET    = 00000010b
            FLAG_LOOP_DELAY     = 00000100b
            FLAG_REPLY_TIMEOUT  = 00001000b
            FLAG_WEIGHT_VALID   = 00010000b
            
            DEFAULT_TIMEOUT     = 5         ; in s

_bss        tm_send             TIMESPEC
            tm_receive          TIMESPEC
            
            lp_timestamp        TIMEVAL
            
            icmp_receive        ICMPHDR
            payload_receive     rb PAYLOAD_SIZE - 8
            receive_hash        dq ?
            
            align 16
            fdread_set:         rb 128
            
            loop_delay          dq ?    ; set with env ICMP_LOOP_DELAY in ms (here in µs)
            hash_seed           dq ?
            sec_latency         dt ?
            msec_latency        dt ?
            ; lp_ftimestamp       dt ?
            min_latency         dt ?
            avg_latency         dt ?
            max_latency         dt ?
            
            gp_buffer           rb 256
            
_data       so_timeout          TIMEVAL DEFAULT_TIMEOUT - 1, 900000
            sel_timeout         TIMEVAL DEFAULT_TIMEOUT, 0
            
            send_ip             SOCKADDR_IN AF_INET
            receive_ip          SOCKADDR_IN AF_INET
            
            icmp_send           ICMPHDR ICMP_ECHO, 0, 1 bswap 2, 1 bswap 2
            payload_send        db "ICMP ping program written with fasm2 assembler!", 0
            tsc_hash            dq 0
            
            PAYLOAD_SIZE = $ - payload_send
            
            flags               db 0
            
            align 4
            receive_ip_size     dd sizeof(SOCKADDR_IN)  ; ugly, but needed for recvfrom()
            
            sent                dd 0
            received            dd 0
            lost                dd 0
            unordered           dd 0
            
_code       Start entry         endbr64
                                push        rdx
                                rdtsc                   ; starting random seed
                                mov         cl, ah
                                shl         rax, 32
                                or          rax, rdx
                                ror         rax, cl
                                mov         [hash_seed], rax
                                pop         rdx
                                nop
                                nop
                                libc.StartMain(&Main);
            align 4                    
            CTRL_C:             endbr64
                                lock or     [flags], FLAG_STOP
                                ret
                                
            Help:               fputs(<"Please specify a host or IPv4 address.",10,0>, [stderr]);
                                mov         eax, 1
                                jmp         Main.end
                                
            Main:               endbr64
                                enter       8, 0    ; fd socket
                                push        rdx     ; +16: *envp[]
                                push        rsi     ;  +8: *argv[]
                                push        rdi     ;  +0: argc
                                
                                mov         rcx, [stderr]
                                mov         rdx, [stdout]
                                push        [rcx]
                                push        [rdx]
                                pop         [stdout]
                                pop         [stderr]
                                
                                cmp         edi, 2
                                jne         Help
                                
                                gethostbyname([rsi+8]);
                                test        rax, rax
                                jz          Help
                                mov         rdx, [rax+HOSTENT.h_addr_list]
                                mov         rdx, [rdx]
                                mov         edx, [rdx]
                                mov         [send_ip.sin_addr], edx
                                
                                signal(SIGINT, &CTRL_C);
                                
                                socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
                                test        eax, eax
                                jns         @f
                                errno();
                                fprintf([stderr], "Couldn't create socket. Error %u: ", dd [rax]);
                                perror(NULL);
                                mov         eax, 2
                                jmp         .end
                        @@      mov         [rbp-8], eax    ; Save socket
                                lock or     [flags], FLAG_OPEN_SOCKET
                                
                                getenv("ICMP_LOOP_DELAY");  ; wait time in milisseconds
                                test        rax, rax
                                jz          @f
                                strtoul(rax, NULL, 10);
                                test        rax, rax
                                jz          @f
                                imul        rax, rax, 1000
                                mov         [loop_delay], rax
                                lock or     [flags], FLAG_LOOP_DELAY    ; set usleep indicator
                                
                        @@      fputs("Pinging to: ", [stdout]);
                                
                                gethostbyaddr(&send_ip.sin_addr, sizeof(IN_ADDR), AF_INET);
                                test        rax, rax
                                jz          @f
                                fprintf([stdout], "'%s' (", [rax+HOSTENT.h_name]);
                                inet_ntoa([send_ip.sin_addr]);
                                fprintf([stdout], "%s) with %u data bytes:%c%c", rax, \
                                    (PAYLOAD_SIZE + sizeof(ICMPHDR) + 20), 10, 10);
                                jmp         @f2
                        @@      inet_ntoa([send_ip.sin_addr]);
                                fprintf([stdout], "%s with %u data bytes:%c%c", rax, \
                                    (PAYLOAD_SIZE + sizeof(ICMPHDR) + 20), 10, 10);
                                
                        @@      setsockopt([rbp-8], SOL_SOCKET, SO_RCVTIMEO, &so_timeout, \
                                    sizeof(TIMEVAL));
                                
                                wait
                                push        1000
                                push        1000000
                                fninit
                                fldz
                                fldz
                                fstp        [max_latency]
                                fstp        [avg_latency]
                                fild        [sel_timeout.tv_sec]
                                fild        [sel_timeout.tv_usec]
                                fidiv       dword [rsp]
                                faddp       st1, st0
                                fimul       dword [rsp+8]
                                fstp        [min_latency]
                                add         rsp, 16
                                
                                lea         rdi, [fdread_set]
                                xor         eax, eax
                                mov         ecx, 128 / 8
                                rep         stosq
                                
                                fflush([stdout]);
                                    
                .loop_ping:     test        [flags], FLAG_STOP
                                jnz         .exit_ping
                                lock and    [flags], not FLAG_REPLY_TIMEOUT
                                
                                gettimeofday(&lp_timestamp, NULL);
                                localtime(&lp_timestamp.tv_sec);
                                strftime(&gp_buffer, 255, "%Y-%m-%d %H:%M:%S.", rax);
                                
                                rdtsc
                                xor         rdx, [tm_send.tv_nsec]
                                shl         rdx, 32
                                mov         eax, eax
                                or          rax, rdx
                                mov         cl, ah
                                xor         rax, [hash_seed]
                                mov         [tsc_hash], rax
                                rol         rax, cl
                                mov         [hash_seed], rax
                                
                                lea         rdi, [gp_buffer]
                                xor         al, al
                                mov         ecx, 256
                                repne       scasb
                                dec         rdi
                                snprintf(rdi, 7, "%06lu", [lp_timestamp.tv_usec]);
                                
                                ; wait
                                ; push        1000000
                                ; fninit
                                ; fild        [lp_timestamp.tv_usec]
                                ; fidiv       dword [rsp]
                                ; fild        [lp_timestamp.tv_sec]
                                ; faddp       st1, st0
                                ; fstp        [lp_ftimestamp]
                                ; add         rsp, 8

                                sendto([rbp-8], &icmp_send, (sizeof(ICMPHDR) + PAYLOAD_SIZE), \
                                    0, &send_ip, sizeof(SOCKADDR_IN));
                                test        rax, rax
                                js          .err_ping
                                inc         [sent]
                                lea         rax, [rax+20] ; length including IP header size
                                push        rax
                                sub         rsp, 8
                                
                                clock_gettime(CLOCK_MONOTONIC, &tm_send);
                                
                                inet_ntoa([send_ip.sin_addr]);
                                
                                movbe       r8w, [icmp_send.echo.id]
                                movbe       r10w, [icmp_send.echo.sequence]
                                movzx       r8, r8w
                                movzx       r10, r10w
                                
                                add         rsp, 8
                                pop         rcx
                                fprintf([stdout], \
                                    <"Sent ITER=%u LEN=%lu ID=%u ",27,"[36mSEQ=%u",27,"[0m ", \
                                    "HASH=%016lX TIMESTAMP=%s TARGET=%s",10,0>, [sent], \
                                    rcx, r8, r10, [tsc_hash], &gp_buffer, rax);
                                fflush([stdout]);
                                
                        @@@     mov         eax, [rbp-8]
                                mov         ecx, 8
                                cdq
                                lea         r11, [fdread_set]
                                div         ecx
                                bts         [r11+rax], rdx
                                
                                mov         edi, [rbp-8]
                                select(&edi+1, &fdread_set, NULL, NULL, &sel_timeout);
                                test        eax, eax
                                js          .err_ping
                                jnz         @f
                                fprintf([stdout], <27,"[33mTimeout at ITER=%u",27,"[0m",10,0>, [sent]);
                                inc         [lost]
                                lock or     [flags], FLAG_REPLY_TIMEOUT
                                jmp         .next_ping
                                
                        @@      clock_gettime(CLOCK_MONOTONIC, &tm_receive);
                                recvfrom([rbp-8], &icmp_receive, (sizeof(ICMPHDR) + PAYLOAD_SIZE), \
                                    NULL, &receive_ip, &receive_ip_size);
                                test        rax, rax
                                jle         .err_ping
                                
                                lea         rsi, [icmp_receive.echo.sequence]   ; accept only 
                                lea         rdi, [icmp_send.echo.sequence]      ; same sequence
                                cmpsw
                                je          @f
                                inc         [unordered]
                                movbe       dx, [icmp_receive.echo.sequence]
                                movzx       rdx, dx
                                fprintf([stdout], <27,"[1;33m", \
                                    "Ignoring too late reply at sequence: %u with hash: %016lX", \
                                    27,"[0m",10,0>, rdx, [receive_hash]);
                                fflush([stdout]);
                                jmp         @@b
                                
                        @@      inc         [received]
                                add         rax, 20
                                
                                wait
                                push        1000
                                push        1000000000
                                fninit
                                fild        [tm_send.tv_sec]      ; st4 = start s
                                fild        [tm_receive.tv_sec]   ; st3 = end s
                                fild        [tm_send.tv_nsec]     ; st2 = start ns
                                fild        [tm_receive.tv_nsec]  ; st1 = end ns
                                fild        qword [rsp]                 ; st0 = 1G
                                fdiv        st1, st0
                                fdivp       st2, st0
                                fadd        st2, st0
                                fincstp
                                ffree       st7
                                faddp       st2, st0            ; st0 = reply, st1 = send
                                fsubrp      st1, st0            ; st0 = latency (s)                        
                                fst         st1
                                fstp        [sec_latency]
                                fimul       dword [rsp+8]       ; st0 = latency (ms)
                                fstp        [msec_latency]
                                wait
                                
                                push        rax
                                sub         rsp, 8
                                inet_ntoa([receive_ip.sin_addr]);
                                add         rsp, 8
                                pop         rcx
                                movbe       r8w, [icmp_receive.echo.id]
                                movbe       r9w, [icmp_receive.echo.sequence]
                                movzx       r8, r8w
                                movzx       r9, r9w
                                fprintf([stdout], \
                                    <"Received ITER=%u LEN=%lu ID=%u ",27,"[36mSEQ=%u",27, \
                                    "[0m HASH=%016lX ",27,"[32mLATENCY: %.3Lfms",27, \
                                    "[0m FROM=%s",10,0>, [sent], rcx, r8, r9, \
                                    [receive_hash], [msec_latency], rax);
                                add         rsp, 16

                .next_ping:     test        [flags], FLAG_REPLY_TIMEOUT
                                jnz         @f
                                lock or     [flags], FLAG_WEIGHT_VALID
                                finit
                                fld         [msec_latency]  ; min and max latency weighting
                                fld         [min_latency]
                                fld         [max_latency]
                                fcomi       st2
                                fcmovb      st0, st2
                                fstp        [max_latency]
                                fcomi       st1
                                fcmovnbe    st0, st1
                                fstp        [min_latency]
                                ffree       st0
                                
                                fld         [avg_latency]   ; average weighting
                                fld         [msec_latency]
                                fild        [received]
                                fild        [received]
                                fld1
                                fsubp       st1, st0
                                fmul        st0, st3
                                fadd        st0, st2
                                fdiv        st0, st1
                                fstp        [avg_latency]
                                emms
                                
                        @@      fputc(10, [stdout]);
                                fflush([stdout]);
                                
                                test        [flags], FLAG_LOOP_DELAY
                                jz          @f
                                usleep([loop_delay]);
                                
                        @@      movbe       dx, [icmp_send.echo.sequence]
                                movbe       cx, [icmp_send.echo.id]
                                add         dx, 1
                                adc         cx, 0
                                movbe       [icmp_send.echo.sequence], dx
                                movbe       [icmp_send.echo.id], cx

                                mov         [sel_timeout.tv_sec], DEFAULT_TIMEOUT ; this needs to be
                                mov         [sel_timeout.tv_usec], 0        ; replenished every loop

                                jmp         .loop_ping
                                
                .err_ping:      test        [flags], FLAG_STOP
                                jnz         .exit_ping
                                errno();
                                fprintf([stderr], "An error (%u) has occurred: ", dd [rax]);
                                perror(NULL);
                                mov         eax, 127
                                jmp         .end
                                
                .exit_ping:     fputs(<10,"Interrupted.",10,0>, [stdout]);
                                test        [flags], FLAG_WEIGHT_VALID
                                jz          @f
                                fprintf([stdout], <"Sent: %u; Received: %u; Lost: %u;", \
                                    " Unordered: %u; Min: %.3Lfms; Avg: %.3Lfms; Max: %.3Lfms%c",0>, \
                                    [sent], [received], [lost], [unordered], [min_latency], \
                                    [avg_latency], [max_latency], 10);
                                jmp         @f2
                        @@      fprintf([stdout], "Sent: %u; Received: %u; Lost: %u%c", \
                                    [sent], [received], [lost], 10);
                        @@      nop
                                
                .end_success:   xor         eax, eax
                .end:           test        [flags], FLAG_OPEN_SOCKET
                                jz          @f
                                push        rax
                                push        rax
                                close([rbp-8]);
                                pop         rax
                        @@      leave
                                ret
