#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <iostream>

#include <ngtcp2/ngtcp2.h>

int main(int argc, char **argv)
{
    seastar::app_template app;

    return app.run(argc, argv, []
                   {
        std::cout << "\n--------------------------------------------------\n";
        std::cout << "TEST INTEGRACJI SEASTAR + NGTCP2\n";
        std::cout << "--------------------------------------------------\n";

        //  Sprawdzenie, czy struktura ngtcp2_info jest dostępna
        const ngtcp2_info* info = ngtcp2_version(0);

        if (info) {
            std::cout << "[SUKCES] Znaleziono bibliotekę ngtcp2!\n";
            std::cout << "  -> Wersja (String): " << info->version_str << "\n";
            std::cout << "  -> Wersja (Num):    0x" << std::hex << info->version_num << std::dec << "\n";
            
            // fix nazwy wersji.
            if (info->version_num == 0x01125a) {
                std::cout << "  -> Weryfikacja: Wersja zgodna z naszym fixem (1.18.90).\n";
            }
        } else {
            std::cout << "[BLAD] Nie udalo sie pobrac informacji o wersji ngtcp2.\n";
        }

        std::cout << "--------------------------------------------------\n\n";

        return seastar::make_ready_future<>(); });
}