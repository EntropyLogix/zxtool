; profile_test.asm - Plik testowy dla profilera zxtool
; Testuje: Hotspots, Branch Prediction, Call Graph, Cycle Counting

    ORG $8000

Entry:
    ; --- 1. Hotspot Test (Pętla) ---
    ; Generuje dużą liczbę "hits" i cykli w małym obszarze
    ld bc, 5000
LoopHot:
    dec bc
    ld a, b
    or c
    jr nz, LoopHot      ; Skok wykonywany 4999 razy, 1 raz nie

    ; --- 2. Function Call & Inclusive Time Test ---
    ; FuncA jest szybka, FuncB jest wolna i woła FuncC
    call FuncA
    call FuncB

    ; --- 3. Branch Prediction Test ---
    ; Pętla z warunkiem parzystości, skok wykonywany w 50% przypadków
    ld b, 20
LoopBranch:
    ld a, b
    and 1
    jr z, IsEven        ; Skok dla liczb parzystych
    nop                 ; Ścieżka dla nieparzystych
    jr NextIter
IsEven:
    nop                 ; Ścieżka dla parzystych
NextIter:
    djnz LoopBranch     ; Skok pętli (Taken 19, Not Taken 1)

    ; --- 4. Block Instruction Test ---
    ; LDIR to jedna instrukcja, która zajmuje dużo cykli (test "Max T-States")
    ld hl, DataSrc
    ld de, DataDst
    ld bc, 16
    ldir

    ; --- 5. Idle Time Test ---
    ; HALT zatrzymuje CPU (profiler powinien to wykryć jako Idle)
    halt

; --- Procedury ---

FuncA:
    ld b, 50
DelayA:
    djnz DelayA
    ret

FuncB:
    ld b, 5
LoopB:
    push bc
    call FuncC          ; Zagnieżdżone wywołanie (zwiększa inclusive time FuncB)
    pop bc
    djnz LoopB
    ret

FuncC:
    ld b, 100
DelayC:
    djnz DelayC
    ret

; --- Dane ---
DataSrc:
    db 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
DataDst:
    ds 16