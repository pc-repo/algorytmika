import socket
import threading
import json
import time
import psutil
import os

global_n = None
global_e = None
process = psutil.Process(os.getpid())


# Żądanie/odbiór klucza publicznego
def prosba(c):
    global global_n, global_e

    long = input("Długość klucza: ")

    try:
        # Wysyłanie żądania
        msg = f"GENERUJ_RSA {long}"
                
        t1 = time.perf_counter()
        cpu_before = process.cpu_times().user
        mem_before = process.memory_info().rss
        
        c.sendall(msg.encode())
        
        # Odbieranie odpowiedzi i weryfikacja
        data = c.recv(4096)

        

        if not data:
            print("Brak danych od serwera.")
            return
        text = data.decode()

        # Próba zdekodowania informacji JSON + obsługa błędów
        try:
            rsa_data = json.loads(text)
            ok = rsa_data.get("status")
            global_n = int(rsa_data.get("A") or rsa_data.get("n"))
            global_e = int(rsa_data.get("B") or rsa_data.get("e"))
            print(f"\n🔑 Otrzymano klucz publiczny RSA:\nn= {global_n}\ne = {global_e}\n")

        except json.JSONDecodeError:
            print("Otrzymano niepoprawny format danych:", data.decode())


        cpu_after = process.cpu_times().user
        mem_after = process.memory_info().rss
        t2 = time.perf_counter()
        print(f"\nCzas oczekiwania na klucz: {t2-t1}")
        cpu_used = cpu_after - cpu_before
        print(f"Zużycie CPU (czas użytkownika): {cpu_used:.6f} s")
        mem_diff = mem_after - mem_before
        print(f"Przyrost pamięci: {mem_diff} B")



    except Exception as err:
        print("Błąd przy żądaniu klucza RSA:", err)
    # return n, e


# Szyfrowanie wiadomości
def encrypt(c, msg):
    global global_n, global_e
    if global_n is None or global_e is None:
        print("❌ Najpierw pobierz klucz RSA komendą: rsa")
    
    else:
    
        plaintext = msg[4:]  # usuń prefiks ENC:
        m = int.from_bytes(plaintext.encode("latin-1"), "big")
        w = pow(m, global_e, global_n)
        w = str(w)
        print(w)
        c.send(f"ENC:{w}".encode())


# Uruchomienie klienta
def laduj(HOST, PORT):
    
    # Ustawienie połączenia
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((HOST, PORT))    
    c.send('Potwierdzam'.encode())

    t = threading.Thread(target=take_of, args=(c,))
    t.daemon = True
    t.start()

    try:
        while True:
            msg = input("Napisz wiadomość (lub 'exit' aby zakończyć): ")
            if msg.lower() == "exit":
                break
            elif msg == "rsa":
                # Wywołanie funkcji proszącej o klucz RSA (socket)       

                prosba(c)

            elif msg.startswith("ENC:"):
                print("Wysłano szyfrem")
                encrypt(c, msg)
                
                   
            else:
                c.send(msg.encode())
    except KeyboardInterrupt:
        pass
    finally:
        c.close()
        print("Połączenie zakończone.")

 # Obsługa wątku klienta   


# Obsługa wątku klienta
def take_of(c):
    c.settimeout(100.0)
    while True:
        try:
            data = c.recv(4096)
            if not data:
                print("Serwer zakończył połączenie.")
                break
            print(f"\nZ SERWERA - wiadomość nieszyfrowana: {data.decode()}")
        except socket.timeout:
            continue
        except ConnectionResetError:
            print("Połączenie z serwerem przerwane.")
            break
        except Exception as e:
            print(f"Błąd odbierania: {e}")
       


if __name__ == "__main__":

    laduj('127.0.0.1', 8888)