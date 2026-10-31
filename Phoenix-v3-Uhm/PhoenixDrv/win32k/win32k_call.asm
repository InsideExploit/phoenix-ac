.code

; extern "C" BOOLEAN InvokeGreProtect(void* Fn, HANDLE a1, HANDLE a2, ULONG a3, ULONG a4);
;
; Windows x64 calling convention:
;   RCX = Fn, RDX = a1, R8 = a2, R9 = a3, [RSP+28h] = a4
; We forward as: Fn(a1, a2, a3, a4)
;
; This asm sidesteps kCFG because MASM does not emit __guard_dispatch_icall_fptr
; wrappers around the CALL. The target is invoked directly, so CFG never sees it.

InvokeGreProtect PROC
    mov r10, rcx            ; save Fn pointer
    mov r11, [rsp+28h]      ; a4 (5th arg on stack) BEFORE we adjust RSP
    mov rcx, rdx            ; a1
    mov rdx, r8             ; a2
    mov r8,  r9             ; a3
    mov r9,  r11            ; a4

    sub rsp, 28h            ; 32-byte shadow space + 8 to realign
    call r10
    add rsp, 28h
    ret
InvokeGreProtect ENDP

END
