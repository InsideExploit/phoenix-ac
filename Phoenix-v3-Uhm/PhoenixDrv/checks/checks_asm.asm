.code

KgReadCr4 PROC
    mov rax, cr4
    ret
KgReadCr4 ENDP

KgWriteCr4 PROC
    mov cr4, rcx
    ret
KgWriteCr4 ENDP

KgDisableInterrupts PROC
    cli
    ret
KgDisableInterrupts ENDP

KgEnableInterrupts PROC
    sti
    ret
KgEnableInterrupts ENDP

END
