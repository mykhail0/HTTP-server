# HTTP-server

Simplistic HTTP-server with limited functionality written in C/C++

## Introduction

This project implements a narrow subset of HTTP/1.1 specification, with specific
behavior in case of resources requested by a client which are unavailable.

## Running

`server <path-to-directory-with-files> <file-with-correlated-servers> [<server's-port's-number>]`

Argument with directory's path is a required parameter and can use either
absolute or relative paths. In case of relative paths, the server tries to find
the given directory in the current working directory. Argument with a link to a
list of correlated servers is also a required parameter, whose function is
specified in a later [section](#correlated-servers). Argument with a port's
number is optional, equal to 8080 by default. The server listens to incoming
connections from clients on this port.

TODO compilation etc

## Specification

On launch, the server finds a given directory with files and starts waiting for
incoming TCP connections on a given port. If either opening the directory,
reading from the directory or opening a network socket does not succeed, the
server exits with `EXIT_FAILURE` error code.

After establishing a connection with a client, the server waits for a client's
request. The server terminates the connection in case of an incorrect request
from a client, after sending an error message with status 400. If the request
is correct, the server waits for more requests from the same client or until the
connection is terminated by the client.

### Communication specification

Every message between a client and the server is of the following form:

```text
HTTP-message = start-line
               *( header-field CRLF )
               CRLF
               [ message-body ]
```

More about this format can be read in the "3. Message format" chapter in the
official
[documentation](https://www.rfc-editor.org/rfc/inline-errata/rfc7230.html) of
HTTP protocol.

#### `start-line`

##### From client

The server accepts only messages where `start-line` is of the `request-line`
format:

```text
request-line = method SP request-target SP HTTP-version CRLF
```

where:

- `method` - is a token specifying the method requested for execution on the
server by the client. Accepted methods by the server are `GET` and `HEAD`.
Method's name is case sensitive,
- `SP` - a single space character,
- `request-target` - identifies a resource on which the client requests the
execution of the given method. This cannot include a space character. In this
implementation, files' names can include onnly characters from [a-zA-Z0-9.-].
Full resource then may include characters from [a-zA-Z0-9.-/],
- `HTTP-version` - the following sequence of characters: `HTTP/1.1`,
- `CRLF` - sequence of 2 characters with ASCII values of 13 and 10.

##### From server

The server replies with messages where `start-line` is of the `status-line`
format:

```text
status-line = HTTP-version SP status-code SP reason-phrase CRLF
```

where:

- `HTTP-version` - the following sequence of characters: `HTTP/1.1`,
- `SP` - a single space character,
- `status-code` - is a number representing status code of the server's reply.
status may indicate the success of the action serverside,
- `reason-phrase` - textual description of the returned status,
- `CRLF` - sequence of 2 characters with ASCII values of 13 and 10.

#### `header-field`

This section contains zero or more lines of the following format:

```text
header-field = field-name ":" OWS field-value OWS
```

gdzie:

```text
ields-name - jest nazwą nagłówka, nieczułą na wielkość liter. W dalszej części zostaną wymienione nagłówki obsługiwane przez naszą implementację serwera.
":" - oznacza literalnie znak dwukropka.
OWS - oznacza dowolną liczbę znaków spacji (w szczególności także brak znaku spacji).
field-value - jest wartością nagłówka zdefiniowaną adekwatnie dla każdego z dozwolonych nagłówków protokołu HTTP. W dalszej części treści zostaną opisane także oczekiwane wartości i znaczenie nagłówków.
```

Przypomnienie: Po wysłaniu wszystkich nagłówków należy zawsze zakończyć tę sekcję znakami CRLF (patrz: Format komunikacji).
Treść komunikatu - message-body

Ostatnim elementem w zdefiniowanym formacie komunikatów, wymienianych pomiędzy serwerem a klientem, jest ich treść (ciało):

```text
                  [ message-body ]
```

Występowanie treści w komunikacie determinuje wystąpienie wcześniej nagłówka Content-Length. Ponieważ w założeniu nasza implementacja obsługuje tylko metody GET i HEAD, to nasz serwer ma prawo z góry odrzucać wszystkie komunikaty klienta, które zawierają ciało komunikatu. Odrzucenie żądania klienta powinno skutkować wysłaniem przez serwer wiadomości z błędem numer 400.

Natomiast nasz serwer wysyłając treść komunikatu musi wysłać także nagłówek Content-length z odpowiednią wartością, szczegóły w dalszej części treści niniejszego zadania.
Zasoby serwera

Nasz serwer podczas startu powinien odczytać obowiązkowy parametr z nazwą katalogu i używać wskazanego katalogu jako miejsca, z którego rozpocznie przeszukiwanie wskazywanych przez klientów zasobów. Nasz serwer traktuje wszystkie identyfikatory zasobów wskazywane przez klientów jako nazwy plików we wskazanym katalogu. Nasz serwer powinien odnajdywać w trakcie swojego działania także pliki, które zostały dodane/usunięte/zmodyfikowane po chwili uruchomienia serwera.

Serwer może założyć, że żądania klientów o zasoby powinny zawsze rozpoczynać się od znaku “/”, który jednocześnie wskazuje nam iż rozpoczynamy poszukiwania pliku od korzenia jakim jest katalog przekazany w parametrze podczas uruchomienia naszego serwera. Jeśli zapytanie klienta nie spełnia tego założenie, to serwer powinien odpowiedzieć błędem o numerze 400.

Serwer powinien traktować kolejne wystąpienia znaku “/”, w identyfikatorze zasobu (request-target), jako znak oddzielający poszczególne nazwy katalogów w ścieżce do pliku. Serwer powinien próbować odnaleźć plik zgodnie ze ścieżką otrzymaną od klienta w identyfikatorze zasobu. W przypadku gdy plik nie zostanie odnaleziony, bądź plik nie jest plikiem zwykłym, do którego serwer ma uprawnienia odczytu, to serwer powinien zachować się zgodnie z wymaganiem opisanym w dalszej części treści zadania ( Skorelowane serwery HTTP).
Obsługa błędów

Nasz serwer powinien w miarę możliwości zawsze wysłać komunikat zwrotny do klienta. Komunikat powinien informować klienta o statusie przetworzenia jego żądania. Sewer powinien zwracać następujące kody (status-code):

```text
200 - ten kod informuje klienta, że jego żądanie zostało w pełni i poprawnie wykonane przez nasz serwer. Ten kod używamy w szczególności kiedy przesyłamy do klienta zawartość szukanego przez klienta pliku.
302 - ten kod oznacza, że szukany przez klienta zasób został tymczasowo przeniesiony pod inną lokalizację. Tego kodu użyjemy do implementacji nietypowego rozszerzenia naszego serwera, opisanym w dalszej części treści zadania (Skorelowane serwery HTTP).
400 - ten kod nasz serwer powinien wysłać zawsze, i tylko w przypadku, kiedy żądanie serwera nie spełnia oczekiwanego formatu, bądź zawiera elementy, które treść zadania wykluczyła jako akceptowane.
404 - ten kod informuje klienta, że żądany przez niego zasób nie został odnaleziony. Nasz serwer powinien wysyłać ten błąd w przypadku nieodnalezienia żądanego przez klienta pliku - z uwzględnieniem jednak dodatkowej logiki opisanej w dalszej części treści zadania (Skorelowane serwery HTTP).
500 - ten kod reprezentuje błąd po stronie naszego serwera w przetwarzaniu żądania klienta. Błąd ten serwer może, i powinien, wysłać do klienta w przypadku problemów występujących po stronie z serwera nie wynikających z błędu po stronie klienta. Ten kod błędu oznacza generyczny błąd pracy serwera.
501 - ten kod błędu serwer może zwrócić w przypadku żądań klienta wykraczających poza skromny zakres implementacji naszego serwera. Dla przykładu wszystkie żądania z metodami różnymi od GET i HEAD. Kod ten informuje klienta, że serwer nie zaimplementował obsługi otrzymanego żądania.
```

Zwracamy uwagę, iż opisane powyżej kody błędów stanowią jedynie wycinek zdefiniowanych błędów standardu HTTP oraz nie pokrywają się dokładnie z poprawną semantyką błędów HTTP (dla przykładu nasz serwer w przypadku błędów 4xx nie zwraca żadnego ciała odpowiedzi, co nie jest zgodne z RFC7231). Zabieg ten pozwolił uprościć implementację zadania, ale student powinien pamiętać, iż niniejsze zadanie w żadnej mierze nie stanowi choćby wycinka referencyjnej implementacji poprawnego serwera protokołu HTTP. Podczas implementacji niniejszego zadania należy postępować zgodnie z zaprezentowaną treścią, a w przypadku wątpliwości zadać pytanie prowadzącym przedmiot. W przyszłości w celu poprawnej implementacji serwera HTTP należy postępować zgodnie z dokumentacją RFC odpowiednią dla implementowanej wersji protokołu HTTP.
Obsługiwane nagłówki

Nasz serwer powinien obsługiwać co najmniej nagłówki o następujących wartościach field-name:

```text
Connection - domyślnie połączenie nawiązane przez klienta powinno pozostać otwarte tak długo jak klient nie rozłączy się albo nasz serwer nie uzna danego klienta za bezczynnego i nie zakończy połączenia. Klient w ramach jednego połączenie może przesłać do serwera więcej niż jeden komunikat i oczekiwać odpowiedzi serwera na każdy z wysłanych komunikatów. Odpowiedzi serwera powinny następować w kolejności odpowiadającej przychodzącym żądaniom klienta. Nagłówek Connection ustawiony z wartością close pozwala zakończyć połączenie TCP po komunikacie odpowiedzi wysłanej przez serwer, następującej po komunikacie zawierającym wspomniany nagłówek ze wskazaną wartością. Zatem jeśli klient wyśle komunikat żądania z nagłówkiem Connection: close, to serwer powinien zakończyć połączenie po wysłaniu komunikatu odpowiedzi. Serwer sam również może zakończyć połączenie, dodając nagłówek Connection: close do swojej odpowiedzi, choć nasz serwer nie powinien się tak zachowywać bez uzasadnionego powodu.
Content-Type - jest nagłówkiem opisującym jakiego rodzaju dane przesyłamy w treści (ciele) komunikatu HTTP. Dzięki wartości tego nagłówka serwer może poinformować klienta czy otrzymany przez niego zasób jest obrazem, tekstem, stroną html, plikiem PDF, etc. Implementacja zadania może zawsze określać wysyłane pliki z serwera jako strumień bajtów application/octet-stream.
Content-Length - wartość tego nagłówka, wyrażona nieujemną liczbą całkowitą, określa długość treści (ciała) komunikatu HTTP. Wartość tego nagłówka jest wymagana w każdej odpowiedzi z serwera, która zawiera treść (ciało). Wartość tego nagłówka określa wyłącznie liczbę oktetów treści (ciała) komunikatu HTTP. Serwer powinien obsługiwać omawiany nagłówek także w komunikatach wysyłanych przez klienta.
Server - jest to parametr opcjonalny jaki serwer może umieszczać w każdym komunikacie wysyłanym do klienta. Wartością tego nagłówka może być dowolny napis indentyfikujący implementację serwera, jego nazwę.
```

Nagłówki nie wymienione powyżej, a otrzymane w komunikacie od klienta ignorujemy.

W przypadku wystąpienia więcej niż jednej linii nagłówka o tej samej wartości field-name, serwer powinien potraktować takie żądanie jako niepoprawne i odpowiedzieć statusem o numerze 400.
Obsługiwane metody

Nasz serwer powinien obsługiwać minimum dwie następujące metody:

```text
GET - w przypadku otrzymania żądania od klienta z tą metodą, serwer powinien podjąć próbę odnalezienia wskazanego zasobu (pliku) w katalogu jaki został przekazany jako parametr przy uruchomieniu programu. Jeśli plik zostanie odnaleziony, to serwer powinien zwrócić zawartość tego pliku poprzez wysłanie odpowiedniego komunikatu HTTP z treścią (ciałem) uzupełnionym oktetami odpowiadającymi bajtom odczytanym z pliku. Serwer powinien ustawić typ zwracanego pliku w nagłówku Content-Type. Dla uproszczenia implementacji serwer może użyć wartości application/octet-stream dla dowolnego pliku.
Jeśli plik nie zostanie odnaleziony na serwerze, to serwer powinien zachować się zgodnie z wymaganiem opisanym w dalszej części treści ( Skorelowane serwery HTTP).
HEAD - w przypadku otrzymania żądania z tą metodą, serwer powinien odpowiedzieć dokładnie takim samym komunikatem jak gdyby otrzymał żądanie z metodą GET, z tą różnicą, że serwer przesyła komunikat bez treści (ciała). Odpowiedź serwera na żądanie HEAD powinna być taka sama jaką otrzymałby klient wykonując metodę GET na wskazanym zasobie, w szczególności nagłówki także powinny zostać zwrócone przez serwer takie same jak w przypadku metody GET.
```

## Correlated servers

Implementacja serwera powinna przyjmować obowiązkowy parametr wejściowy wskazujący (ścieżką bezwzględną bądź względną) na plik tekstowy o strukturze:

zasób TAB serwer TAB port

gdzie:

```text
zasób - to bezwzględna ścieżka do pliku.
TAB - znak tabulacji.
serwer - to adres IP serwera, na którym wskazany zasób się znajduje. Adres jest adresem IP w wersji 4.
port - to numer portu, na którym serwer nasłuchuje na połączenia.
```

Serwer powinien odszukać plik na podstawie ścieżki bezwzględnej bądź ścieżki względnej w aktualnym katalogu roboczym. Jeśli plik nie zostanie odnaleziony, bądź nie możliwe było jego odczytanie, to serwer powinien zakończyć swoje działanie z kodem błędu EXIT_FAILURE. Implementacja serwera może założyć, że wczytywany plik posiada poprawną strukturę, zgodną z zadaną w niniejszej treści zadania, a plik pusty także jest poprawnym plikiem. Implementacja serwera powinna odczytać zawartość pliku i w przypadku otrzymania od klienta żądania HTTP dotyczącego zasobu, którego serwer nie znalazł w plikach zlokalizowanych lokalnie, powinien przeszukać wczytaną z pliku tablicę i odszukać żądany przez klienta zasób. Jeśli zasób nie występuje także we wczytanej tablicy, to serwer powinien odpowiedzieć statusem o numerze 404 do klienta. Jeśli jednak zasób znajduje się na liście, to serwer powinien wysłać odpowiedź do klienta ze statusem numer 302 oraz ustawionym nagłówkiem Location, którego wartość powinna być tekstem reprezentującym adres HTTP do serwera zawierającego szukany zasób. Jeśli szukany zasób występuje więcej niż raz w tablicy wczytanej z pliku, to serwer powinien skorzystać z pierwszego wpisu występującego najwcześniej w pliku. Konstruowanie nowego adres szukanego zasobu należy wykonać następującego:

PROT serwer COLON port zasób

gdzie:

```text
PROT - to napis http://.
serwer - to adres IP serwera, odczytany z pliku.
COLON - to znak dwukropka.
port - to numer portu, odczytany z pliku.
zasób - to bezwzględna ścieżka do zasobu (zaczynająca się od znaku slash /).
```

Dodatkowe wymagania

Katalog z rozwiązaniem powinien zawierać pliki źródłowe oraz plik Makefile zapewniający automatyczną kompilację i linkowanie. Po wywołaniu komendy "make", na serwerze students, program musi się poprawnie kompilować. Do komunikacji sieciowej należy używać wyłącznie omawianego na zajęciach mechanizmu gniazd z biblioteki standardowej.
Format rozwiązania:

Jako rozwiązanie należy wysłać poprzez moodle plik ab123456.tar.gz, gdzie ab123456 to login na students. W wysłanym powinien znaleźć się katalog ab123456 zawierający pliki źródłowe i plik Makefile.

We wspomnianym katalogu proszę nie umieszczać plików binarnych ani żadnych plików pośrednich powstających podczas kompilacji. W wyniku wykonania polecenia make powinien powstać plik wykonywalny: serwer.

Ponadto Makefile powinien obsługiwać cel (target) 'clean', który po wywołaniu kasuje wszystkie pliki powstałe podczas kompilacji.
