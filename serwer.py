import socket
import threading
import time
import random
import json
from math import gcd
import psutil
import os

global_n = None
global_d = None
global_len = 2048
process = psutil.Process(os.getpid())


# Nasłuchiwacz zdarzeń i przesyłanie klucza RSA + obsługa błędów
def listen_to(client):
    while True:
        try:
            data = client.recv(1024)
            if not data:
                print("Klient zakończył połączenie.")
                break

            
            try:
                msg = data.decode().strip()
            except UnicodeDecodeError:
                print("Odebrano dane binarne do dekodowania.")
                continue

            print(f"\n\n[OD KLIENTA] {msg}")



            parts = msg.split()
            cmd = parts[0]
            global_len = parts[1] if len(parts) > 1 else None


            # obsługa komendy generowania RSA
            if cmd.upper() == "GENERUJ_RSA":
                print("Żądanie od klienta: wygeneruj klucz RSA.")
                try:


                    t1 = time.perf_counter()
                    cpu_before = process.cpu_times().user
                    mem_before = process.memory_info().rss

                    n, e, d = generate_rsa_fixed(global_len)   # generowanie prametrów RSA
                    # n, e, d = generate_rsa()   # generowanie prametrów RSA


                    cpu_after = process.cpu_times().user
                    mem_after = process.memory_info().rss
                    t2 = time.perf_counter()
                    print(f"\nCzas generacji klucza: {t2-t1}")
                    cpu_used = cpu_after - cpu_before
                    print(f"Zużycie CPU (czas użytkownika): {cpu_used:.6f} s")
                    mem_diff = mem_after - mem_before
                    print(f"Przyrost pamięci: {mem_diff} B")


                except Exception as err:
                    print("Błąd generowania RSA:", err)

                    # odsyłamy ewentualną informację o błędzie do klienta
                    resp = {"status": "error", "msg": str(err)}
                    client.sendall(json.dumps(resp).encode())
                    continue

                # wysyłamy tylko klucz publiczny (n, e) — nigdy d
                resp = {"status": "ok", "n": str(n), "e": str(e)}
                
                # konwertujemy liczby do stringów żeby uniknąć problemów z JSON (bezpieczne)
                client.sendall(json.dumps(resp).encode())
                print("Wysłano klucz publiczny (n,e) do klienta.")
                continue

            # Obsługa odczytu wiadomości szyfrowanej
            elif msg.startswith("ENC:"):
                print("coś szyfrem")
                
                msg = msg[4:]

                print(msg)
                # enc_msg to string otrzymany od klienta, np. "1234567890123456789"
                cif = int(msg)  # zamiana na liczbę całkowitą

                # RSA decryption: M = C^D mod N

                t10 = time.perf_counter()
                cpu_before_1 = process.cpu_times().user
                mem_before_1 = process.memory_info().rss

                m = pow(cif, global_d, global_n)  # N to modulus, ten sam co w kluczu publicznym
                print(m)

                cpu_after_1 = process.cpu_times().user
                mem_after_1 = process.memory_info().rss
                t11 = time.perf_counter()
                print(f"Czas potęgowania: {t11-t10}")
                cpu_used_1 = cpu_after_1 - cpu_before_1
                print(f"\nZużycie CPU (czas użytkownika): {cpu_used_1:.6f} s")
                mem_diff_1 = mem_after_1 - mem_before_1
                print(f"Przyrost pamięci: {mem_diff_1} B")



                # Zamiana liczby z powrotem na tekst
                msg_decrypted = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("latin-1")
                print("Odszyfrowana wiadomość:", msg_decrypted)


        except ConnectionResetError:
            print("Połączenie z klientem przerwane.")
            break
        except Exception as e:
            print(f"Błąd odbierania: {e}")
            break
    client.close()


# Uruchomienie serwera
def startuj(HOST, PORT, message):

    # Ustawienie połączenia
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()

    client, addr = s.accept()
    print(f"Rozpoczynam nasłuchiwanie na :  {HOST}:{PORT}")
    print(f"DO KLIENTA - wiadomość nieszyfrowana:  {message}")
    client.sendall(message.encode())

    t = threading.Thread(target=listen_to, args=(client,))
    t.daemon = True
    t.start()


    try:
        while True:
            msg = input("Napisz wiadomość (lub 'exit' aby zakończyć): ")
            if msg.lower() == "exit":
                break
            client.sendall(msg.encode())
    except KeyboardInterrupt:
        pass
    finally:
        print("Zamykanie połączenia...")
        client.close()
        s.close()


# Generuj liczbę pierwszą
def generate_prime_old(max, exclude):
        
        while True:
            a = random.randint(800000000000, max)
            if a == exclude: continue
            if a % 2 == 0: continue
            for i in range(3, int(a**0.5)+1, 2):
                if a % i == 0:
                    break
            else:
                return a
            
# Generuj liczbę pierwszą - test Rabina-Millera
def generate_prime(min, max, exclude):
        
        while True:
            a = random.randint(min, max)
            if a == exclude: continue
            if a % 2 == 0: continue
            if miller_rabin(a, k=40):
                return a
            
            
# Test R-M
def miller_rabin(n, k=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # rozkład n−1 = d · 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True           

# Oblicz funkcję Eulera            
def generate_n_phi(prime_a, prime_b):

    n = prime_a * prime_b
    phi = (prime_a - 1) * (prime_b - 1)
    return n, phi


# Wybór wykładnika szyfrowania (e)
# Algorytm Euklidesa (prosty) - biblioteka "math"
def generate_e(phi):

    while True:
        e = random.randint(3, phi - 1)
        if gcd(e, phi) == 1:
            return e


# Generowanie wykładnika deszyfrowania (d)
# Algorytm Euklidesa rozszerzony
def generate_d(e, phi):

    t, new_t = 0, 1
    r, new_r = phi, e
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise Exception("Brak odwrotności modularnej")
    if t < 0:
        t = t + phi
    return t


# Algorytm RSA - pełna implementacja                
def generate_rsa():

    global global_n, global_d
    min, max = n_bit(63)
    p = generate_prime(min, max, None)
    q = generate_prime(min, max, p)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d = generate_d(e, phi)
    global_d = d
    global_n = n
    # print("Typ e:", type(e))
    # print("Typ phi:", type(phi))
    # print(f"{p}, {q}, {n}, {e}, {d}")

    bit_length = e.bit_length()
    print(f"\nDokładna długość klucza: {bit_length} bit")
    print(min.bit_length())
    print(max.bit_length())
    
    return n, e, d


# Algorytm RSA - określona długość               
def generate_rsa_fixed(x):

    global global_n, global_d
    
    x = int(x)
    y = x // 2
    min, max = n_bit(y)

    while True:
        p = generate_prime(min, max, None)
        q = generate_prime(min, max, p)
        n = p * q
        if n.bit_length() == x:
            break   # mamy idealny rozmiar

    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d = generate_d(e, phi)
    global_d = d
    global_n = n

    bit_length = n.bit_length()
    print(f"\nDokładna długość klucza: {bit_length} bit")
    
    return n, e, d



def n_bit(n):
    min_val = 2**(n-1)
    max_val = 2**n - 1
    return min_val, max_val


if __name__ == "__main__":

    startuj('127.0.0.1', 8888, "Połączenie otwarte..")
   
    # a, b, c = generate_rsa()
    # print(a, b, c)   