# Dziennik zmian RPC/QUIC

Ten plik sluzy jako notatnik zmian wykonywanych podczas przygotowywania obecnego RPC do obslugi QUIC. Kolejne zmiany warto dopisywac tutaj od razu po ich wprowadzeniu: co zostalo zmienione, dlaczego i jaki jest nastepny sensowny krok.

## 1. Wydzielenie abstrakcji transportu w `rpc::connection`

W klasie `rpc::connection` bezposrednie pole `_connected`, ktore trzymalo `connected_socket`, `input_stream` i `output_stream`, zostalo zastapione abstrakcja `connection::transport`.

Nowy transport udostepnia cztery podstawowe operacje:

- `input()` zwraca strumien wejsciowy.
- `output()` zwraca strumien wyjsciowy.
- `shutdown_input()` zamyka kierunek odczytu.
- `shutdown_output()` zamyka kierunek zapisu.

Dla obecnego TCP dodany zostal adapter `connected_socket_transport`, tworzony w `connection::set_socket()`. Dzieki temu aktualne RPC nadal dziala po TCP tak jak wczesniej, ale kod `connection` nie musi juz znac szczegolow `connected_socket`.

Cel tej zmiany: przygotowac miejsce, w ktorym pozniej mozna podstawic transport QUIC bez przepisywania calej logiki RPC.

## 2. Nazwane obiekty `incoming_request` i `incoming_response`

Dodane zostaly struktury:

- `internal::incoming_request`
- `internal::incoming_response`

Wczesniej kod klienta i serwera bezposrednio rozpakowywal tuple zwracane przez parser ramek, np. `msg_id`, `handler_duration`, `data`, `expire`, `type`. Teraz sa do tego metody:

- `client::receive_response()`
- `server::connection::receive_request()`

Na razie te metody nadal czytaja dane z obecnego strumienia TCP przez `transport_input()`. Zmiana jest jednak wazna architektonicznie, bo tworzy jedno miejsce, w ktorym QUIC bedzie mogl pozniej zwrocic request odczytany z konkretnego streamu.

Cel tej zmiany: odkleic petle przetwarzania RPC od szczegolow formatu zwracanego przez parser ramek i przygotowac request/response jako jawne obiekty protokolu.

## 3. Rozszerzenie `reply_handle`

`internal::reply_handle` przestal byc pustym znacznikiem. Teraz zawiera move-only funkcje wysylajaca gotowy bufor odpowiedzi:

```cpp
noncopyable_function<future<> (snd_buf&&, std::optional<rpc_clock_type::time_point>)>
```

Dla obecnego TCP `connection::make_reply_handle()` tworzy uchwyt, ktory nadal wysyla odpowiedz przez stara sciezke:

```cpp
connection::send(std::move(data), timeout)
```

Sciezka odpowiedzi zostala przepieta tak, aby:

- `incoming_request` niosl `reply_handle`.
- Wewnetrzny `rpc_handler_func` dostawal `reply_handle`.
- `reply()` w `rpc_impl.hh` przekazywal `reply_handle` do `server::connection::respond(...)`.
- `unknown_verb` rowniez odsylal blad przez `reply_handle`.

Dla TCP zachowanie pozostaje takie samo. Roznica polega na tym, ze odpowiedz nie jest juz na sztywno zwiazana z glownym polaczeniem TCP. Dla QUIC bedzie mozna stworzyc `reply_handle`, ktory zapisze odpowiedz na ten sam QUIC stream, z ktorego przyszedl request.

Cel tej zmiany: przygotowac mechanizm odpowiedzi per-request/per-stream, potrzebny do modelu QUIC, gdzie jedno polaczenie moze miec wiele niezaleznych streamow.

## 4. Odbior requestu przez transport po stronie serwera

Rozszerzona zostala abstrakcja `connection::transport` o metode:

```cpp
future<internal::incoming_request> receive_request(connection& owner)
```

Oznacza to, ze transport zaczyna decydowac nie tylko o tym, jaki ma `input_stream` i `output_stream`, ale rowniez o tym, skad serwer ma odebrac kolejny request RPC.

Dla obecnego TCP implementacja pozostaje prosta:

- `connected_socket_transport::receive_request()` uzywa swojego `_input`,
- wywoluje `owner.receive_request_frame(_input)`,
- `server::connection::receive_request_frame()` parsuje standardowa ramke RPC,
- tworzony jest zwykly TCP `reply_handle` przez `make_reply_handle()`.

`server::connection::receive_request()` nie czyta juz bezposrednio z `transport_input()`. Zamiast tego deleguje do:

```cpp
transport_receive_request()
```

Dzieki temu petla serwera nie musi wiedziec, czy request przyszedl z jednego TCP streamu, czy w przyszlosci z osobnego QUIC streamu.

Cel tej zmiany: przesunac odpowiedzialnosc za odbior requestu do warstwy transportu. To jest bezposredni punkt wejscia dla QUIC, gdzie implementacja `receive_request()` bedzie mogla zaakceptowac lub odebrac nowy QUIC stream i zbudowac `incoming_request` z `reply_handle` wskazujacym na ten stream.

W tej zmianie są właściwie dwa różne “handlery”, łatwo je pomylić.

Pierwszy to RPC handler użytkownika. To jest funkcja zarejestrowana przez protocol.register_handler(...). Ona obsługuje konkretny verb RPC, np. “dodaj”, “pobierz dane”, “ping”. Tego nie zmieniamy publicznie.

Drugi to reply_handle, czyli uchwyt mówiący: “gdzie odesłać odpowiedź”. To nie obsługuje requestu. To obsługuje tylko wysyłkę odpowiedzi.

Przed zmianą było mniej więcej tak:

serwer czyta request z TCP
  -> znajduje RPC handler
  -> RPC handler liczy wynik
  -> reply()
  -> server::connection::respond()
  -> connection::send()
  -> TCP output
Czyli odpowiedź zawsze szła przez connection::send(), a więc przez główne połączenie TCP.

Po zmianie jest tak:

transport czyta request
  -> tworzy incoming_request
  -> incoming_request ma reply_handle
  -> serwer znajduje RPC handler
  -> RPC handler liczy wynik
  -> reply()
  -> server::connection::respond(reply_handle)
  -> reply_handle.send(...)
Dla TCP reply_handle.send(...) nadal robi:

connection::send(std::move(data), timeout)
Więc zachowanie TCP jest takie samo.

Ale dla QUIC reply_handle.send(...) będzie mogło robić coś innego, np.:

stream.write(std::move(data))
Najważniejsza idea:

RPC handler odpowiada na pytanie: co zrobić z requestem?
reply_handle odpowiada na pytanie: którędy wysłać odpowiedź?
Dlatego to jest potrzebne pod QUIC. Przy QUIC wiele requestów może przyjść na różnych streamach w jednym połączeniu. Serwer musi wiedzieć, że odpowiedź do requestu z stream A ma wrócić na stream A, a odpowiedź do requestu z stream B na stream B. reply_handle przenosi właśnie tę informację.

## 5. Hook wysylania requestu po stronie klienta

Rozszerzona zostala abstrakcja `connection::transport` o metode:

```cpp
future<> send_request(connection& owner, snd_buf&& data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel)
```

Oznacza to, ze klient nie musi juz wysylac requestu bezposrednio przez `connection::send(...)`. Zamiast tego `client::request()` po zakodowaniu naglowka RPC wywoluje:

```cpp
transport_send_request(std::move(buf), timeout, cancel)
```

Dla obecnego TCP implementacja `connected_socket_transport::send_request()` robi dokladnie to samo co poprzednio:

```cpp
owner.send(std::move(data), timeout, cancel)
```

Celowo nie zostala zmieniona mapa `_outstanding`. Klient nadal rejestruje oczekujaca odpowiedz pod `msg_id`, a petla odbioru odpowiedzi nadal dopasowuje response do handlera przez `msg_id`. Dzieki temu timeouty, cancellation i istniejaca semantyka RPC pozostaja po staremu.

Cel tej zmiany: przygotowac miejsce, w ktorym transport QUIC bedzie mogl pozniej otworzyc nowy stream dla requestu, wyslac na nim ramke RPC, a odpowiedz dalej przekazac do obecnego mechanizmu `_outstanding`.

## 6. Konstruktor serwerowego connection z gotowym transportem

Dodany zostal nowy konstruktor `server::connection`, ktory przyjmuje gotowy transport:

```cpp
connection(server& s, std::unique_ptr<transport> transport, socket_address&& addr, const logger& l, void* serializer, connection_id id)
```

Stary konstruktor TCP pozostaje bez zmian:

```cpp
connection(server& s, connected_socket&& fd, socket_address&& addr, const logger& l, void* serializer, connection_id id)
```

Nowy konstruktor inicjalizuje bazowe `rpc::connection` bez socketu, a potem ustawia przekazany transport przez `set_transport(std::move(transport))`.

Przy okazji typ `connection::transport` zostal przeniesiony do publicznej czesci `rpc::connection`, zeby kod budujacy transport QUIC mogl go nazwac i przekazac do konstruktora. Samo ustawianie transportu nadal pozostaje kontrolowane przez `set_transport()`.

Cel tej zmiany: umozliwic utworzenie `server::connection` bez `connected_socket`. To jest potrzebne dla QUIC, bo polaczenie RPC nie bedzie wtedy bezposrednio owijalo TCP socketu, tylko QUIC transport zarzadzajacy streamami.

## 7. Pierwsza implementacja `quic_server_transport`

Dodany zostal nowy naglowek:

```cpp
include/seastar/rpc/rpc_quic_transport.hh
```

W naglowku znajduje sie pierwsza klasa transportu QUIC dla serwera:

```cpp
rpc::experimental::quic_server_transport
```

Klasa dziedziczy po:

```cpp
rpc::connection::transport
```

i trzyma:

- `quic::experimental::connection` jako polaczenie QUIC,
- `quic::experimental::stream` jako control stream uzywany przez istniejaca negocjacje RPC,
- `input_stream<char>` i `output_stream<char>` utworzone z control streamu.

Metody `input()` i `output()` zwracaja strumienie control streamu. Dzieki temu istniejacy etap negocjacji RPC moze nadal uzyc standardowego mechanizmu `receive_negotiation_frame()` / `send_negotiation_frame()`.

Najwazniejsza metoda to:

```cpp
future<internal::incoming_request> receive_request(connection& owner)
```

Jej dzialanie:

- czeka na kolejny QUIC stream przez `_conn.accept_stream()`,
- tworzy `input_stream<char>` i `output_stream<char>` z tego streamu,
- parsuje standardowa ramke RPC przez `owner.receive_request_frame(input)`,
- podmienia `request.reply` na QUIC-owy `reply_handle`,
- ten `reply_handle` zapisuje zakodowana odpowiedz RPC na `output_stream<char>` tego samego QUIC streamu.

Wspolny helper `write_snd_buf(...)` zapisuje `snd_buf` do dowolnego `output_stream<char>`. Obecna sciezka TCP tez z niego korzysta, wiec unikamy dublowania logiki zapisu buforow.

Cel tej zmiany: miec pierwszy rzeczywisty adapter RPC-over-QUIC po stronie serwera. Serwerowa petla RPC nadal widzi zwykle `incoming_request`, ale fizycznie request moze przyjsc z osobnego QUIC streamu, a odpowiedz wraca na ten sam stream.

## 8. Helpery do tworzenia RPC connection z QUIC session

Dodane zostaly dwa helpery w `rpc::server`:

```cpp
shared_ptr<connection> make_quic_connection(quic::experimental::connection session, quic::experimental::stream control_stream, connection_id id)
future<> handle_quic_session(quic::experimental::connection session)
```

`make_quic_connection(...)`:

- pobiera adres peer z QUIC session,
- tworzy `rpc::experimental::quic_server_transport`,
- przekazuje transport do fabryki protokolu `_proto.make_server_connection(...)`,
- zwraca gotowe `server::connection`.

`handle_quic_session(...)`:

- sprawdza `filter_connection`, tak samo jak TCP accept path,
- akceptuje pierwszy QUIC stream jako `control_stream`,
- tworzy `connection_id`,
- buduje RPC connection przez `make_quic_connection(...)`,
- rejestruje connection w `_conns`,
- uruchamia `conn->process()` w tle.

Zeby helper mogl uzyc wlasciwego serializera protokolu, `protocol_base` dostal drugi overload:

```cpp
make_server_connection(server&, std::unique_ptr<connection::transport>, socket_address, connection_id)
```

Konkretny `protocol<Serializer, MsgType>` implementuje go analogicznie do TCP, ale zamiast `connected_socket` przekazuje gotowy transport do konstruktora `server::connection`.

Cel tej zmiany: przygotowac brakujacy klej miedzy `quic::experimental::connection` a istniejacym RPC serverem. Po tym kroku kod akceptujacy QUIC connection moze wywolac `handle_quic_session(...)`, a reszta przetwarzania idzie przez standardowy `server::connection::process()`.

## 9. Publiczna petla accept dla QUIC RPC servera

Dodana zostala metoda:

```cpp
void server::accept_quic(quic::experimental::quic_server& qs)
```

Metoda uruchamia w tle petle:

```cpp
qs.accept()
  -> handle_quic_session(session)
```

`server` nie przejmuje ownership nad `quic_server`. Oznacza to, ze kod uzywajacy tej sciezki nadal odpowiada za:

- utworzenie `quic_server`,
- wywolanie `quic_server.start(config)`,
- wywolanie `rpc_server.accept_quic(quic_server)`,
- zatrzymanie `quic_server.stop()` przy zamykaniu aplikacji.

Ten wariant jest celowo maly i bezpieczny, bo nie zmienia cyklu zycia istniejacego `rpc::server`. Pozwala natomiast szybko spiac demo lub test, w ktorym QUIC listener dostarcza sesje do istniejacego RPC servera.

Cel tej zmiany: wystawic pierwszy publiczny punkt podlaczenia QUIC servera do RPC servera bez wprowadzania jeszcze nowego ownership modelu ani konstruktora `server` przyjmujacego `quic_server_config`.

## 10. Wydzielenie obslugi response po stronie klienta

Po stronie klienta dodane zostaly dwie metody pomocnicze:

```cpp
future<internal::incoming_response> receive_response_frame(input_stream<char>& in)
void handle_response(internal::incoming_response response)
```

`receive_response_frame(...)` czyta standardowa ramke RPC response z podanego `input_stream<char>`. Obecna metoda `receive_response()` zostala uproszczona i teraz tylko wywoluje:

```cpp
receive_response_frame(transport_input())
```

`handle_response(...)` zawiera logike, ktora wczesniej byla bezposrednio w `client::loop()`:

- pobiera `msg_id`,
- szuka handlera w `_outstanding`,
- przekazuje payload do oczekujacego reply handlera,
- aktualizuje statystyki `handler_duration`,
- obsluguje spoznione odpowiedzi i odpowiedzi wyjatkowe.

`client::loop()` dla TCP nadal czyta odpowiedzi z glownego `transport_input()`, ale teraz po odczycie robi tylko:

```cpp
auto response = co_await receive_response();
handle_response(std::move(response));
```

Cel tej zmiany: przygotowac klienta QUIC. Przyszly `quic_client_transport` bedzie mogl otworzyc per-request stream, odczytac response przez `receive_response_frame(stream.input())`, a potem dostarczyc wynik do istniejacej mapy `_outstanding` przez `handle_response(...)`.

## Nastepny krok

Nastepny logiczny etap to dodanie klientowego transportu QUIC. Po stronie klienta `send_request()` powinno:

- otworzyc nowy QUIC stream,
- zapisac request frame na ten stream,
- odczytac response frame z tego samego streamu,
- przekazac response do obecnego mechanizmu `_outstanding` po `msg_id`.

Na tym etapie `_outstanding` zostaje jako warstwa dopasowania odpowiedzi do `msg_id`.

## 11. Pierwsza implementacja `quic_client_transport`

Dodana zostala klasa:

```cpp
rpc::experimental::quic_client_transport
```

Klasa dziedziczy po:

```cpp
rpc::connection::transport
```

i podobnie jak serwerowy transport trzyma:

- `quic::experimental::connection`,
- `quic::experimental::stream control_stream`,
- `input_stream<char>` i `output_stream<char>` control streamu dla negocjacji RPC.

Najwazniejsza metoda to:

```cpp
future<> send_request(connection& owner, snd_buf&& data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel)
```

Jej dzialanie:

- otwiera nowy QUIC stream przez `_conn.open_stream()`,
- zapisuje zakodowany request frame na `output_stream<char>` tego streamu,
- flushuje i zamyka output stream,
- uruchamia w tle odczyt response z `input_stream<char>` tego samego streamu,
- odczytany response przekazuje do `client::handle_response(...)`.

Wazna decyzja: `send_request()` nie czeka na response. Zwraca po wyslaniu requestu i uruchomieniu background readera. To zachowuje dotychczasowa semantyke RPC:

```cpp
when_all(client.request(...), wait_for_reply(...))
```

`client.request(...)` odpowiada za wysylke, a `wait_for_reply(...)` nadal odpowiada za timeout, cancellation i wynik RPC przez `_outstanding`.

Na razie argument `cancellable* cancel` nie jest jeszcze podpiety do anulowania QUIC streamu. Obecna implementacja zachowuje mapowanie odpowiedzi przez `_outstanding`, ale nastepny krok powinien dopiac cancellation do resetowania request streamu.

Cel tej zmiany: dodac klientowy odpowiednik `quic_server_transport`, w ktorym kazdy request RPC moze byc wyslany na osobnym QUIC streamie, a odpowiedz z tego streamu wraca do istniejacego mechanizmu reply handlerow.

## 12. Konstruktor klienta z gotowym transportem

Dodany zostal konstruktor `rpc::client`, ktory przyjmuje gotowy transport:

```cpp
client(const logger& l, void* s, client_options options, std::unique_ptr<transport> transport, const socket_address& addr, const socket_address& local = {}, bool read_responses_from_transport = false)
```

Analogiczny konstruktor zostal dodany do `protocol<Serializer, MsgType>::client`, zeby uzytkownik protokolu mogl utworzyc klienta na custom transporcie bez dotykania niskopoziomowego serializera.

Wydzielone zostaly tez wspolne metody klienta:

```cpp
feature_map make_client_features() const
future<> process_client_connection(bool read_responses_from_transport)
future<> loop_with_transport(bool read_responses_from_transport)
```

TCP uzywa:

```cpp
process_client_connection(true)
```

czyli po negocjacji dalej czyta odpowiedzi z glownego transport input streamu.

QUIC klient bedzie uzywal:

```cpp
process_client_connection(false)
```

czyli control stream sluzy do negocjacji i utrzymania connection loop, ale response nie sa czytane z control streamu. Response sa czytane w tle przez `quic_client_transport` z per-request streamow i trafiaja do `client::handle_response(...)`.

`client::stop()` zostal uzupelniony tak, zeby zamykal rowniez abstrakcyjny transport przez `shutdown_transport_input()` i `shutdown_transport_output()`. To jest potrzebne dla klientow bez realnego TCP socketu, np. klienta QUIC.

Cel tej zmiany: umozliwic utworzenie zwyklego `rpc::client` na transporcie innym niz TCP socket, w szczegolnosci na `quic_client_transport`.
