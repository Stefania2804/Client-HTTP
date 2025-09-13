Salomia Maria Stefania 321CD

# Client HTTP pentru Management Biblioteca de Filme

Acest program este un client in linia de comanda scris in C pentru a interactiona cu un API de management al unei biblioteci de filme. Permite operatiuni administrative (management utilizatori) si operatiuni pentru utilizatori obisnuiti (management filme si colectii).

## Descriere

Clientul comunica cu un server HTTP (detaliile serverului, cum ar fi `SERVER_HOST` si `SERVER_PORT`, sunt definite in `client.h`). Utilizeaza request-uri HTTP (GET, POST, PUT, DELETE) pentru a efectua diverse actiuni. Datele sunt schimbate cu serverul in format JSON.

Clientul mentine starea sesiunii prin cookie-uri (pentru admin si utilizator) si token-uri JWT (pentru acces la biblioteca).

## Utilizarea Bibliotecii Parson pentru JSON

Pentru manipularea datelor in format JSON (JavaScript Object Notation), acest client utilizeaza biblioteca **Parson (versiunea 1.5.3)**. JSON este un format standard deschis, usor de citit de oameni si usor de parsat/generat de masini, fiind frecvent utilizat in comunicarea API-urilor web.

**Motivele alegerii Parson includ:**

1.  **Simplitate si Usurinta in Utilizare:** Parson ofera un API simplu si intuitiv pentru crearea, parsarea si accesarea datelor JSON. Functiile sunt bine definite si usor de inteles, ceea ce reduce complexitatea codului client.
2.  **Dimensiune Redusa (Lightweight):** Parson este o biblioteca mica, constand dintr-un singur fisier sursa (`parson.c`) si un fisier header (`parson.h`). Acest lucru o face ideala pentru proiecte unde dependintele mari nu sunt dorite sau pentru medii cu resurse limitate. Integrarea in proiect este simpla, prin simpla adaugare a acestor doua fisiere in procesul de compilare.
3.  **Performanta Buna:** Desi este simpla, Parson este conceputa pentru a fi eficienta in parsarea si serializarea JSON-ului.
4.  **Independenta de Platforma:** Este scrisa in C standard, facand-o portabila pe diverse sisteme de operare.
5.  **Managementul Memoriei:** Parson gestioneaza alocarea si eliberarea memoriei pentru structurile JSON, simplificand dezvoltarea si reducand riscul de memory leaks daca este utilizata corect (de ex., prin apelarea `json_value_free` pentru obiectele radacina parsate sau create).
6.  **Suport pentru Tipuri de Date JSON Standard:** Suporta toate tipurile de date JSON: obiecte, array-uri, string-uri (cu suport UTF-8), numere (double), booleeni si `null`.
7.  **Licenta Permisiva (MIT):** Licenta MIT sub care este distribuit Parson permite utilizarea libera in proiecte comerciale si non-comerciale, cu putine restrictii.

**Cum este utilizata in proiect:**

*   **Crearea Payload-urilor JSON:** Pentru request-urile POST si PUT care necesita un corp de cerere in format JSON (de ex., la autentificare, adaugarea unui utilizator, film sau colectie), Parson este folosit pentru a construi structura JSON. Functii precum `json_value_init_object()`, `json_object_set_string()`, `json_object_set_number()` sunt utilizate pentru a crea obiectul JSON, care este apoi serializat intr-un string cu `json_serialize_to_string()` pentru a fi trimis in corpul request-ului HTTP.
*   **Parsarea Raspunsurilor JSON:** Cand serverul returneaza date in format JSON (de ex., la obtinerea listei de utilizatori, filme, detalii despre un film sau token-uri), string-ul JSON din corpul raspunsului HTTP este parsat folosind `json_parse_string()`. Acest lucru creeaza o structura `JSON_Value` in memorie, din care datele specifice pot fi extrase folosind functii precum `json_value_get_object()`, `json_object_get_array()`, `json_object_get_string()`, `json_object_get_number()`, etc.
*   **Eliberarea Memoriei:** Dupa ce datele JSON au fost procesate, memoria alocata de Parson este eliberata folosind `json_value_free()` pentru obiectul JSON radacina si `json_free_serialized_string()` pentru string-urile serializate.

In concluzie, Parson ofera un echilibru bun intre simplitate, performanta si usurinta de integrare pentru necesitatile de manipulare JSON ale acestui client.

## Functionalitati

Programul suporta urmatoarele comenzi, introduse interactiv in linia de comanda:

### Comenzi Admin

*   **`login_admin`**: Autentifica un administrator.
    *   Cere: `username`, `password`.
    *   Salveaza un cookie de sesiune admin.
*   **`logout_admin`**: Delogheaza administratorul curent.
    *   Necesita: Cookie de sesiune admin activ.
*   **`add_user`**: Adauga un nou utilizator (non-admin) in sistem.
    *   Necesita: Cookie de sesiune admin activ.
    *   Cere: `username`, `password` pentru noul utilizator.
*   **`get_users`**: Afiseaza lista tuturor utilizatorilor din sistem.
    *   Necesita: Cookie de sesiune admin activ.
*   **`delete_user`**: Sterge un utilizator din sistem.
    *   Necesita: Cookie de sesiune admin activ.
    *   Cere: `username`-ul utilizatorului de sters.

### Comenzi Utilizator

*   **`login`**: Autentifica un utilizator obisnuit.
    *   Cere: `admin_username` (al adminului care a creat utilizatorul), `username`, `password`.
    *   Salveaza un cookie de sesiune utilizator.
*   **`logout`**: Delogheaza utilizatorul curent.
    *   Necesita: Cookie de sesiune utilizator activ.
*   **`get_access`**: Obtine un token JWT pentru a accesa resursele bibliotecii.
    *   Necesita: Cookie de sesiune utilizator activ.
    *   Salveaza token-ul JWT.
*   **`get_movies`**: Afiseaza lista tuturor filmelor disponibile in biblioteca.
    *   Necesita: Token JWT activ.
*   **`get_movie`**: Afiseaza detaliile unui film specific.
    *   Necesita: Token JWT activ.
    *   Cere: `id`-ul filmului.
*   **`add_movie`**: Adauga un film nou in biblioteca.
    *   Necesita: Token JWT activ.
    *   Cere: `title`, `year`, `description`, `rating`.
*   **`delete_movie`**: Sterge un film din biblioteca.
    *   Necesita: Token JWT activ.
    *   Cere: `id`-ul filmului de sters.
*   **`update_movie`**: Actualizeaza detaliile unui film existent.
    *   Necesita: Token JWT activ.
    *   Cere: `id`-ul filmului si noile valori pentru `title`, `year`, `description`, `rating` (campurile pot fi lasate goale pentru a nu le modifica).
*   **`get_collections`**: Afiseaza lista colectiilor de filme create de utilizatorul curent.
    *   Necesita: Token JWT activ.
*   **`get_collection`**: Afiseaza detaliile unei colectii specifice (inclusiv filmele continute).
    *   Necesita: Token JWT activ.
    *   Cere: `id`-ul colectiei.
*   **`add_collection`**: Creeaza o noua colectie de filme si, optional, adauga filme in ea.
    *   Necesita: Token JWT activ.
    *   Cere: `title` pentru colectie, `num_movies` (numarul de filme de adaugat initial) si apoi `movie_id` pentru fiecare film.
*   **`delete_collection`**: Sterge o colectie de filme.
    *   Necesita: Token JWT activ.
    *   Cere: `id`-ul colectiei de sters.
*   **`add_movie_to_collection`**: Adauga un film existent intr-o colectie existenta.
    *   Necesita: Token JWT activ.
    *   Cere: `collection_id` si `movie_id`.
*   **`delete_movie_from_collection`**: Sterge un film dintr-o colectie.
    *   Necesita: Token JWT activ.
    *   Cere: `collection_id` si `movie_id`.

### Comenzi Generale

*   **`exit`**: Inchide clientul.
