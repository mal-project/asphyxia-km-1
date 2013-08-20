; template v.1.5 (release)
;.......................................................................
MIN_NAMELEN		= 8
MIN_VERIDLEN    = 4
MAX_VERIDLEN    = 5

;.......................................................................
AUTOUPDATE      = 0
PAINTBG         = 1
PAINTINFBG      = 0
;.......................................................................

include biglib.inc
includelib biglib.lib
.const
    ; Little trick to hide string in Olly. Seach for Text String
    ; wont work because of null start strings.
    ; How ever, you must reference this string this way : [offset szString]+1
    ; But not a compilation time, thus this way will avoid this trick.

	szSUCCESS   db  0,"Congratulations!   ",0,"You just defeated this protection.",13,10,"Now you should share your knowledge with others.",13,10,"Make a tutorial on how you reverse it.",0

	szERR	    db	0,"Registration failed",0,"Invalid registration info.",13,10,"Please check your registration and try again.",0
	
	; Our public exponenet
	hE          db  0,"ECCA",0
	
	; Our modulus N, itsnt? sup'
	; Our modulus is bad. This is not the modulus. First 4 chars are bad.
	; If you want do something with it you must delete these chars.
	; How ever, bigN will be correct thus _BigIn will receive chars at
	; offset hN+4
	hN1          db  0,"BD2DBD2874A5E8A973B68CCC3F634D4AE8C9FC14131DE424A8E717831381B479A889",0
	hN2          db  0,"A554E658191A64DDEAF221A16013993C573E44B329B2D14132BE1A25223A9E81",0
.data

    db  "We shall not cease from exploration,",0
    db  "and the end of all our exploring",0
    db  "will be to arrive where we started",0
    db  "and know the place for the first time.",0
    
.data?
    ddFlag          dd  ?           ; Flag para determinar si la registracion fue existosa o no
    ddNameLen       dd  ?           ; to check for name length
    ddVersionLen     dd  ?          ; 
	
	szName		db	50	dup(?)      ; buffer for name
	szSerial	db	680	dup(?)      ; buffer for serial (yeah, it can be really big)
    szVersionID	db  6   dup(?)      ; four chars. These chars are fixed ones. Keep reading to know why and how
	
	pM          dd  ?               ; Plain text  (M)
	pC          dd  ?               ; Cypher text (C)
	pC2         dd  ?               ; Never used
	pE          dd  ?               ; E
	pN          dd  ?               ; N

;.......................................................................
.code
__KEYGEN__ proc
    sub     esp,124h

    ; M = szName^E mod N
    ; KEY = M * szNameLen
    ; X = K^E mod N
    push    1
;.......................................................................
; M = C^E mod N
    ; creatin big vars
    ; *N                ; modulus N
    push    0
    call    _BigCreate
    mov     pN, eax     ; saving pointer
    
    ; *E                ; public exponent E
    push    0
    call    _BigCreate
    mov     pE, eax
    
    ; asshole stuff
    lea     ebx,[hE]    ; Reference to our modulus E
    mov     ecx,dword ptr [hFlagDbg]                ; IsDebuggerPresent
    push    ebx         ; *
    
    ; *C                ; Cypher text
    push    0
    call    _BigCreate
    mov     pC, eax

    ; *C2              ; Never used
    push    0
    call    _BigCreate
    mov     pC2, eax
    ; asshole stuff
    pop     ebx         ; *
	
	; *M                ; plain text
	push    0
	mov     ecx,dword ptr [ecx]                     ; IsDebuggerPresent
	call    _BigCreate
	mov	    pM,eax
	
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
	; asshole stuff
    push    ebx         ; Reference to hE
    mov     eax,1       ; Avoid first null char
    
    or      eax,ecx     ; IsDebuggerPresent
    
    add     eax,ebx     ; Reference completed (olly will show our E)
   
    ; big number
    ; E                 ; public exponent
    push    pE
    push    16
    push    eax         ; Here olly show our E
    xor     eax,eax
    call    _BigIn
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ; N                 ; modulus N
    ;must be F0FF (61695) = 
    ; F0FF - BFB1 == 314Eh
    
    ;comment ~
    mov     edx,dword ptr [szVersionID]     ; we use version id to
                                            ; reference hE. Obviously
                                            ; its a fixed value (rva)
                                            ; until modify and recompilation

    push    edx                         ; give us our szVersionID
    call    toHex
    add     esp,4
    ; ie: "1337" will return 00001337h
    ; this is why acceptable chars are only hex ones

    sub     eax,0BFB1h                      ; In order to make it a little bit harder
    mov     ecx,hInst                       ; Our base
    mov     cx,0ffffh                       ; To keep rva
    add     eax,ecx
    and     eax,0FFF0FFFFh                  ; 0040xxxx
    ;comment ~
    
    ;mov     eax,offset hE
    sub     eax,0dh
    push    pN                                 ; This line were 3 hours of debugging and dispair
    push    16                                  ; radix
    push    eax                                 ; hN1
    call    _BigIn

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ; M                 ; Plain text
    push    pM
    push    16
    push    offset szSerial
    call    _BigIn
    
    push    pE
    push    1337h
    push    pE
    call    _BigAdd32
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ; making C = M^E mod N
    push    pC              ; cipher text
    push    pN              ; N1 (modulus)
    push    pE              ; 10001 (public exponent)
    push    pM              ; szSerial
    call    _BigPowMod
	;invoke	_BigPowMod,big,bigexp,bigmod,bigresult
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     ecx,dword ptr [hFlagDbg]                ; IsDebuggerPresent

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    lea     ebx,[hN2]
	; asshole stuff
    ;push    ebx         ; Reference to hN
    mov     ecx,dword ptr [ecx]
    mov     eax,1       ; Avoid first null char
    
    or      eax,ecx     ; IsDebuggerPresent
    
    add     eax,ebx     ; Reference completed (olly will show our N2)
   
    ; big number
    ; E                 ; public exponent
    push    pN
    push    16
    push    eax         ; Here olly show our E
    xor     eax,eax
    call    _BigIn

    ; making C = C^E mod N
    push    pC              ; Cipher text
    push    pN              ; N2 (modulus)
    push    pE              ; 10001 (public exponenet)
    push    pC              ; Cipher text
    call    _BigPowMod
	;invoke	_BigPowMod,big,bigexp,bigmod,bigresult

    ; M                 ; Plain text
    push    pM
    push    16
    push    offset szName
    call    _BigIn

    push    pM
    push    1988h
    push    pM
    call    _BigSub32
    
    push    pM              ; cipher text = szName ^ E mod N2
    push    pN              ; N2 (modulus)
    push    pE              ; 10001 (public exponent)
    push    pM              ; szName - 1988
    call    _BigPowMod
	;invoke	_BigOut,pC2,16,addr szSerial      ; hex output of Serial
    ;INVOKE SetDlgItemText, hWnd, IDC_ID, ADDR sId
    
    push    pM              ; (szName - 1988)^E mod N2
    push    pC              ; (szSerial ^ E mod N1)^E mod N2
    call    _BigCompare
    push    eax
    ;invoke  wsprintf,addr hBUFFER,addr szFORMAT,eax

    ; (szName - 1988)^E mod N2 == szSerial^E mod N2

    ;invoke 	lstrcpy,addr szSerial,addr szERR
    
_end:
    invoke _BigDestroy, pN
    invoke _BigDestroy, pE
    invoke _BigDestroy, pC
    invoke _BigDestroy, pC2         ; never used
    invoke _BigDestroy, pM
    pop     eax
    cmp     eax,-1
    jnz     @F
        mov     eax,1
    @@:
    mov     dword ptr [ddFlag],eax
    push    eax
    xor     eax,eax
    push    ebx
    push    dword ptr [ecx]
    call    dword ptr [edi]
    add     esp,124h
    add     esp,8h
    ret
__KEYGEN__ endp

;.......................................................................
KEYGENPROC proc     hWnd:DWORD
	push    offset SEH		    ; empujo mi SEH
	mov     eax,fs:[0]		    ; 
	push    eax			        ; empujo el final del SEH
	mov     fs:[0],esp          ; y finalmente SEH_fin -> MYSEH -> SEH System
	
    push	sizeof szName
    push	offset szName
    push	IDE_NAME
    push	[ebp+8]
    call	[dword ptr hGetDlgItemTextA]
    
    mov		dword ptr ddNameLen,eax

    push	sizeof szSerial
    push	offset szSerial
    push	IDE_SERIAL
    push	[ebp+8]
    call	[dword ptr hGetDlgItemTextA]
    mov     dword ptr [ddFlag],1h
    
    push	sizeof szVersionID
    push	offset szVersionID
    push	IDE_VERSIONID
    push	[ebp+8]
    call	[dword ptr hGetDlgItemTextA]
    mov		dword ptr ddVersionLen,eax
    	
	push    offset szERR
    ; checking name len	
	cmp     [ddNameLen],MIN_NAMELEN
	jnb      _LenghtValid
        comment ~
            add     ebx,2
            pop     edx
            sub     edx,1
            inc     edx
            inc     edx
            push    edx
            push    offset szSerial
            call    lstrcpy
        comment ~
            
            jmp     _ends
        
	_LenghtValid:
    cmp     [ddVersionLen],MIN_VERIDLEN
    jnz      _ends
        mov     ecx,[ddNameLen]
        xor     edx,edx
        _next:
        mov     al,byte ptr [szName+edx]
        cmp     al,41h
        jnb     @F          ; >= 41h
            mov     byte ptr [szName+edx],78h
            jmp     _passby
        @@:
        cmp     al,5Ah
        jbe     _passby     ; is upcase letter
        
        cmp     al,61h
        jnb     @F
            mov     byte ptr [szName+edx],78h
            jmp     _passby
        @@:
        cmp     al,7Ah
        jbe     _passby
            mov     byte ptr [szName+edx],78h
        _passby:
        inc     edx
        cmp     ecx,edx
        ja      _next
        
        call	__KEYGEN__
        add     esp,0ch
_ends:
    inc     edx
    inc     edx
    push    edx
    call    dword ptr [esi]
    ;push	offset szSerial
    ;push	IDE_SERIAL
    ;push	[ebp+8]
    ;call	SetDlgItemText
    ret
KEYGENPROC endp
;.......................................................................
SEH:
    ; if dword ptr [ddFlag] == 0, you defeated this protection
    ; if not... you probably are gay. lol
    mov     ecx,dword ptr [ddFlag]
    lea     eax,offset szSUCCESS
    imul    ecx,092h
    add     eax,ecx

    inc     eax
    mov     edx,eax
    add     edx,20
    push    MB_ICONINFORMATION + MB_OK + MB_TOPMOST
    push    eax
    push    edx
    push    hWndGlobal
    call    [dword ptr hMessageBoxA]

    push    0
    call    ExitProcess
    ret
;.......................................................................
toHex proc  string:DWORD
    mov     ebx,edx         ; our dword
    xor     edx,edx         ; where store results
    mov     ecx,4
    
_NEXT:
	mov		al,bl			; byte
	ror     ebx,8
    rol     edx,4
    
	.if eax > 29h && eax < 40h
    
        xor     eax,30h
    
    .elseif eax > 40h && eax < 47h
    
        sub     eax,37h
        
    .endif
    
        add     edx,eax
    dec     ecx
    cmp     ecx,0
    jnz     _NEXT
    mov     eax,edx
    pop     edx
    jmp     dword ptr [esp]
    
; return with error    
_RETURNERR:
    mov     dword ptr[ebx],0F0ADh   ; Fuck Off and Die!
_RETURNERR2:
    pop     ecx
    pop     edx
    call    edx
_RETURNERR1:
    push    eax
    push    offset [1337h]
    call    ebx
    
    pop     ecx
    ret
toHex endp