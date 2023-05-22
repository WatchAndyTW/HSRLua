.code

;Avoid NtProtectVirtualMemory hook

extern vp_syscall:dword

virtual_protect proc frame
.endprolog
	mov r10, rcx
	mov eax, vp_syscall
	syscall
	ret
virtual_protect endp

end