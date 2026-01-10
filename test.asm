ORG $C000

Main PROC
    CALL Test
    ; Example 1: Clear to White Paper, Black Ink
    LD A, $38               ; %00111000 (Paper 7, Ink 0)
    CALL FastCLS

    HALT                    ; Wait for interrupt (simple delay)

    ; Example 2: Clear to Black Paper, Yellow Ink
    LD A, $06               ; %00000110 (Paper 0, Ink 6)
    CALL FastCLS

    JP $
Main ENDP

Test PROC
    LD A, $FF
    RET
ENDP

; ================================================================
; Procedure: FastCLS
; Purpose:   Clears the screen pixels and sets color attributes.
; Input:     A = Attribute byte (Format: FBPPPIII)
;            (e.g., $38 = Flash 0, Bright 0, Paper 7, Ink 0)
; ================================================================
SCREEN_ADDR EQU $4000       ; Start of pixel memory
PIXEL_SIZE  EQU $1800       ; Size of pixel area (6144 bytes)
ATTR_SIZE   EQU $0300       ; Size of attribute area (768 bytes)

FastCLS PROC
    ; --- Save Registers ---
    PUSH BC                 ; Preserve BC
    PUSH DE                 ; Preserve DE
    PUSH HL                 ; Preserve HL
    PUSH AF                 ; Preserve Accumulator (Color) for later

    ; --- Step 1: Clear Bitmap (Pixels) ---
    LD HL, SCREEN_ADDR      ; Source: Start of screen memory
    LD DE, SCREEN_ADDR + 1  ; Dest:   Next byte
    LD BC, PIXEL_SIZE - 1   ; Count:  Total pixels - 1
    LD (HL), 0              ; Clear the first byte (set to 0)
    
    LDIR                    ; Copy (HL) to (DE), repeating BC times.
                            ; This effectively "floods" the pixel area with 0.

    ; --- Step 2: Set Attributes (Colors) ---
    ; Optimization note: After LDIR, HL points exactly to $5800 
    ; (Start of Attributes) and DE points to $5801.
    
    POP AF                  ; Restore the Color byte from stack into A
    
    LD (HL), A              ; Set the first attribute byte
    LD BC, ATTR_SIZE - 1    ; Count: Total attributes - 1
    
    LDIR                    ; Flood the attribute area with the color in A.

    ; --- Restore Registers ---
    POP HL                  ; Restore HL
    POP DE                  ; Restore DE
    POP BC                  ; Restore BC
    
    RET                     ; Return from procedure
FastCLS ENDP