# Intrukcja kompilacji

`make all` zbuduje program **raise**, który można włączyć poleceniem `./raise <plik core>`

# Opis rozwiązania

Program **raise** jest linkowany pod niski adres. W tym celu jest wykorzystywany jest skrypt linkera, który ostawia standardowy adres ładowania na 0x00048000. Program **raise** zmienia adres stosu na 0x07648000 oraz ustawia jego wielkośc na 8MB. W takim kontekście odmapowuje wszystko z przestrzni użytkownika co leży powyżej standardowego rejestru ładowania.

Następnie przetwarzany jest plik elf, mapowane są odpowiednie fragmenty programu oraz zostaje ustawione TLS (o ile informacja o TLS dostępna w corze). Zostaje wywołany plik assemblerowy, który ładuje odpowiednie rejestry ogólnego przeznaczenia, ustawia rejestr `eflags`, oraz instrukcją `jmp` ustawia odpowiednią wartość rejetru `eip`.