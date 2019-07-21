.comm ebx_value,4,4
.comm ecx_value,4,4
.comm edx_value,4,4
.comm esi_value,4,4
.comm edi_value,4,4
.comm ebp_value,4,4
.comm eax_value,4,4
.comm eip_value,4,4
.comm eflags_value,4,4
.comm esp_value,4,4

.section .text
.global loadRegisters
.type loadRegisters, @function

loadRegisters:
movl ebx_value, %ebx
movl ecx_value, %ecx
movl edx_value, %edx
movl esi_value, %esi
movl edi_value, %edi
movl ebp_value, %ebp
movl eax_value, %eax
movl esp_value, %esp
push eflags_value
popf
jmp *eip_value
