; template v.1.5 (keygen)
;.......................................................................
.486
.model flat, stdcall
option casemap :none
assume fs:nothing

include		windows.inc

include		kernel32.inc
includelib	kernel32.lib

include		user32.inc
includelib	user32.lib

include		gdi32.inc
includelib	gdi32.lib

include		masm32.inc
includelib	masm32.lib

include macros.asm
;.......................................................................

; Prototypes (however mostly i dont use invoke)
MAINDLGPROC 	PROTO	:HWND,:UINT,:WPARAM,:LPARAM
INFODLGPROC 	PROTO	:HWND,:UINT,:WPARAM,:LPARAM

; Resource IDs
IDI_ICON    = 100

IDD_DLG     = 200
IDD_INF     = 201

IDC_IMG     = 300

IDE_NAME    = 400
IDE_SERIAL  = 401
IDE_VERSIONID    = 402
IDE_INF     = 403

IDB_GEN     = 410
IDB_CLOSE   = 411
IDB_INF     = 412
IDB_CLSINF  = 413

IDR_INF     = 500
IDR_REL     = 501
IDR_RGN     = 502

IDR_MUS     = 600

;.......................................................................
.const
	CR_DLGBG	dd	0aaaaaaah
.data

.data?
    hInst			dd		?
    pReleaseData	LPCTSTR	?       ; Release data

    hPatternBrush	HBRUSH	?
    hDlgBgColor     HBRUSH  ?       ; Background color for info dlg
    
    hWndGlobal      dd      ?
    hFlagDbg        dd      ?
    
;.......................................................................
.code
	include release.asm

Start:
    pushad
    
    push	0
    call	GetModuleHandle
    mov		hInst,eax
    mov     dword ptr [hFlagDbg],ebx
	push	0
	push	MAINDLGPROC
	push	0
	push	IDD_DLG
	push	hInst
	call	DialogBoxParam
	
	push    hPatternBrush
	call    DeleteObject
	
	popad
	
	push	0
	call	ExitProcess
ret

;.......................................................................

MAINDLGPROC proc hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	.if uMsg == WM_INITDIALOG
        IF AUTOUPDATE
            push    hWin
            call    KEYGENPROC
		ENDIF
		
		mov     eax,hWin
		mov     dword ptr [hWndGlobal],eax
		mov     eax,hInst
		; Restoring bytes (must be fixed each compilation)
		; almo must see write attributes at code section
        ;db 0A1h, 10h, 43h, 40h, 00h ; mov eax,hInst
        comment ~
        db 0C6h, 80h, 0CEh, 41h, 00h, 00h, 41h ; mov [base64 table],41h
        db 0C6h, 80h, 9Eh, 21h, 00h, 00h, 0Fh  ; BigLib (KANAL)
        db 0C6h, 80h, 56h, 23h, 00h, 00h, 0Fh  ; BigLib (KANAL)
        db 0C6h, 80h, 33h, 15h, 00h, 00h, 51h  ; _BigCreate (x3chung crypto searcher) - original byte 0x51
        db 0C6h, 80h, 60h, 15h, 00h, 00h, 51h  ; _BigDestroy (x3chung crypto searcher) - original byte 0x51
comment ~
		call    FindK32Address
		push    42Fh
        call    FindAPIAddress
		;invoke  SetWindowPos,hWin,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE+SWP_NOSIZE
        invoke ShowWindow,hWin,SW_SHOW
	
	.elseif uMsg == WM_CTLCOLORDLG
	
		mov     eax, hPatternBrush
		ret

	.elseif uMsg == WM_COMMAND
	
		mov		eax,wParam
		.if ax == IDB_INF			; button info

			push	0
			push	INFODLGPROC
			push	hWin
			push	IDD_INF
			push	hInst
			call	DialogBoxParam
        
        IF AUTOUPDATE
		
		.elseif ax == IDE_NAME || ax == IDE_COMP        ; input box
            
            shr     eax,16
            .if ax == EN_CHANGE
                push    hWin
                jmp     KEYGENPROC
                
            .endif
        
        ELSE
        
        .elseif ax == IDB_GEN       ; gen button
                
                push    hWin
                call    KEYGENPROC

        ENDIF
        
		.elseif ax == IDB_CLOSE		; close button

			push	0
			push	hWin
			call	EndDialog

		.endif

	.elseif uMsg == WM_CLOSE || uMsg == WM_LBUTTONDBLCLK

		push	0
		push	hWin
		call	EndDialog

	.elseif uMsg == WM_LBUTTONDOWN
	
		push	0
		push	HTCAPTION
		push	WM_NCLBUTTONDOWN
		push	hWin
		call	SendMessage

	.endif
	
	xor		eax,eax
	ret

MAINDLGPROC endp

FindK32Address proc
    push	[offset SEH1]		; empujo mi SEH
    mov		eax,fs:[0]		; 
    push	eax			; empujo el final del SEH
    mov		fs:[0],esp      ; y finalmente SEH_fin -> MYSEH -> SEH System
    
    ;finding kernel32.dll address
    mov		eax,dword ptr [esp+010h]	; return user32.dll
    and 	eax,0FFFFF000h

    continue_search:
        sub 	eax,1000h
        cmp		eax,0
        jl		stop_search		
        cmp		word ptr [eax],"ZM"
    jnz		continue_search
    
    jmp		found
    
    stop_search:
        add		esp,8
        push    2h
        push    eax
        call    dword ptr [edi]
        ret
    
    found:
        mov		dword ptr hUser,eax
        mov		eax,0
        add		esp,8
        ret

    SEH1:
        mov esp,dword ptr [esp+8]
        mov fs:[0],esp
    jmp continue_search
        
FindK32Address endp

FindAPIAddress proc

    ; obtenemos el PE header
    mov		edi,dword ptr hUser
    mov 	eax,[edi + 3ch]
    add		eax,edi ; el desplazamiento imageBase + desplazamiento = real virtual address
    mov		dword ptr hPEHeader,eax
    
    ; encontrando la tabla de exportaciones
    mov		edi, dword ptr hPEHeader
    mov		eax,[edi + 78h]		; el desplazamiento de la table desde el pe header
    add     eax, dword ptr hUser
    mov		dword ptr hExpTable,eax
    
    ; address of names
    mov     edi, dword ptr hExpTable
    mov     eax, dword ptr [edi + 020h]
    add     eax, dword ptr hUser
    mov     dword ptr hAddressOfNames, eax


_FINDAPIS:
    mov     eax, dword ptr hAddressOfNames
    mov     dword ptr hContador, 0
    xor     ebx, ebx                           
    sub     ebx, 4

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
FindGetProc:
    push    eax
    inc     dword ptr hContador
    add     ebx, 4 
    push    ebx
    mov     edx, [eax + ebx] 
    add     edx, dword ptr hUser
    mov     esi, edx        ; in esi will be kernel apis
    
    xor     eax,eax
    xor     ecx,ecx
    xor     ebx,ebx
__:
    mov     al,byte ptr [esi+ecx]
    add     ebx,eax
    inc     ecx
    cmp     eax,0
    jnz     __
    
    cmp     ebx,[esp + 0Ch]
    pop     ebx
    pop     eax
    jnz     FindGetProc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    dec     dword ptr hContador

    mov     edx, [eax + ebx] 
    add     edx, dword ptr  hUser
    
    ; address of ordinals
    mov		ecx, dword ptr hExpTable
    mov		ecx,[ecx + 24h];AddressOfNameOrdinals esta a 24h desde el comienzo de la tabla de exportaciones
    add		ecx,dword ptr hUser
    ; ecx va a quedar apuntando al comienzo de la table AddressOfNameOrdinals
    
    ;para apuntar a algun valor, en este caso el indice para apuntar a GetProcAddress
    ;tenemos que multiplicar este valor por 2, ya que cada valor de la tabla ocupa 2 bytes
    
    mov     eax, dword ptr hContador			; el indice
    add     dword ptr hContador, eax          ; multiplicamos por dos
    add     ecx, dword ptr hContador
    
    ;consigo AddressOfFunctions
    mov		ebx, dword ptr hExpTable
    mov     ebx, [ebx + 1Ch]		;que esta a 1Ch desde el comienzo de la table de exportaciones
    ;add     ebx, [ebp + offset szKernel]
    add     ebx, dword ptr hUser

    movzx   eax, word ptr [ecx]
    rol     eax, 2                                     ; multiplico * 4, por lo mismo que la anterior, solo que ahora ocupa dw
    add     ebx, eax                                   ; ‘normalizo’ la RVA
    mov     eax, [ebx]
    add     eax, dword ptr hUser
    
    cmp     dword ptr hMessageBoxA,0
    jnz     @F
        mov     dword ptr hMessageBoxA,eax
        jmp     _nextapi
    @@:
        mov     dword ptr hGetDlgItemTextA,eax
    _nextapi:
    
    cmp     dword ptr hGetDlgItemTextA,0
    pop     eax
    push    5ACh
    push    eax
    jz      _FINDAPIS
   
    ret
    ; ok ya tenemos la direccion del PE header
FindAPIAddress endp	

    hUser           dd      0
    hPEHeader       dd      0
    hExpTable       dd      0
    hAddressOfNames dd      0
    hContador       dd      0
    hGetProcAddress dd      0
    ;hAPIS           dd      42Fh,5ACh;MessageBoxA,GetDlgItemTextA
    hFindFirst      dd      0
    ;hGetProc        db      "GetProcAddress",0
    hMessageBoxA    dd      0
    hGetDlgItemTextA    dd  0

;.......................................................................

INFODLGPROC PROC hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM
	.if uMsg == WM_INITDIALOG
		push	RT_RCDATA
		push	IDR_INF
		push	hInst
		call	FindResource

		push	eax
		push	hInst
		call	LoadResource

		push	eax
		call	LockResource

		mov		pReleaseData, eax

		push	pReleaseData
		push	IDE_INF
		push	hWnd
		call	SetDlgItemText
		
		IF PAINTINFBG
            invoke  CreateSolidBrush, CR_DLGBG
            mov     hDlgBgColor, eax
        ENDIF
		
    IF PAINTINFBG
	
	.elseif uMsg == WM_CTLCOLORDLG
		mov     eax, hDlgBgColor
		ret
	
	ENDIF
	
	.elseif uMsg == WM_COMMAND

		.if wParam == IDB_CLSINF
			push	0
			push	0
			push	WM_CLOSE
			push	hWnd
			call	SendMessage
		.endif
		
	.elseif uMsg == WM_CLOSE
	
		push	0
		push	hWnd
		call	EndDialog
	
	.elseif uMsg == WM_LBUTTONDOWN
	
		push	0
		push	HTCAPTION
		push	WM_NCLBUTTONDOWN
		push	hWnd
		call	SendMessage

	.endif
	
	xor eax, eax
	ret
INFODLGPROC ENDP
end Start