// ProyectoPrograIII.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <fstream>

using namespace std;
string usuarioLogeado;

class SHA256 {
private:
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t rotr(uint32_t n, uint32_t d) {
        return (n >> d) | (n << (32 - d));
    }

    uint32_t sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    uint32_t sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    uint32_t Sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    uint32_t Sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    vector<uint8_t> padMessage(const string& input) {
        vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);
        while ((padded.size() * 8) % 512 != 448) {
            padded.push_back(0x00);
        }
        uint64_t msgLength = input.size() * 8;
        for (int i = 7; i >= 0; --i) {
            padded.push_back((msgLength >> (i * 8)) & 0xFF);
        }
        return padded;
    }

public:
    string hash(const string& input) {
        uint32_t H[] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        vector<uint8_t> padded = padMessage(input);

        for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
            uint32_t W[64] = { 0 };
            for (int i = 0; i < 16; ++i) {
                W[i] = (padded[chunk + (i * 4)] << 24) | (padded[chunk + (i * 4) + 1] << 16) |
                    (padded[chunk + (i * 4) + 2] << 8) | padded[chunk + (i * 4) + 3];
            }
            for (int i = 16; i < 64; ++i) {
                W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
            }

            uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
                uint32_t T2 = Sigma0(a) + Maj(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
            }

            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        stringstream ss;
        for (uint32_t h : H) {
            ss << hex << setw(8) << setfill('0') << h;
        }
        return ss.str();
    }
};

class Usuario {
public:
    string nombUsuario;
    string contrasena;

    Usuario(string nombUsuario, string contrasena) {
        this->nombUsuario = nombUsuario;
        this->contrasena = contrasena;
    };

    static void registarUsuario(string nombUsuario, string contrasena) {
        ofstream archivo("usuarios.txt", ios::app);
        archivo << nombUsuario << endl;
        archivo << contrasena << endl;
        archivo.close();
    };

    static bool iniciarSesion(string nombUsuario, string contrasena) {
        ifstream archivo("usuarios.txt");
        string nombUsuarioArchivo, contrasenaArchivo;

        while (getline(archivo, nombUsuarioArchivo)) {
            getline(archivo, contrasenaArchivo);
            if (nombUsuario == nombUsuarioArchivo && contrasena == contrasenaArchivo) {
                archivo.close();
                usuarioLogeado = nombUsuario;
                return true;
            }
        }
        archivo.close();
        return false;
    };
};

class GestorSaldos {
public:
    static double obtenerSaldo(const string& usuario) {
        ifstream archivo("saldos.txt");
        string nombre;
        double saldo;

        while (archivo >> nombre >> saldo) {
            if (nombre == usuario) {
                archivo.close();
                return saldo;
            }
        }

        archivo.close();
        return 1000.0; 
    }

    static void actualizarSaldo(const string& usuario, double nuevoSaldo) {
        ifstream archivo("saldos.txt");
        vector<pair<string, double>> saldos;
        string nombre;
        double saldo;
        bool encontrado = false;

        while (archivo >> nombre >> saldo) {
            if (nombre == usuario) {
                saldos.push_back({ nombre, nuevoSaldo });
                encontrado = true;
            }
            else {
                saldos.push_back({ nombre, saldo });
            }
        }
        archivo.close();

        if (!encontrado) {
            saldos.push_back({ usuario, nuevoSaldo });
        }

        ofstream salida("saldos.txt");
        for (auto& par : saldos) {
            salida << par.first << " " << par.second << endl;
        }
        salida.close();
    }

    static void transferir(const string& remitente, const string& destinatario, double monto) {
        double saldoRem = obtenerSaldo(remitente);
        double saldoDest = obtenerSaldo(destinatario);
        actualizarSaldo(remitente, saldoRem - monto);
        actualizarSaldo(destinatario, saldoDest + monto);
    }
};

struct Transaccion {
    double monto;
    string id;
    string remitente;
    string destinatario;
    string hash;
    string fecha;
    Transaccion* siguiente;
    Transaccion* anterior;

    Transaccion() {
        monto = 0.0;
        siguiente = nullptr;
        anterior = nullptr;
    }
};

class ListaTransacciones {
private:
    int contador;
    Transaccion* primero;
    Transaccion* ultimo;

public:
    ListaTransacciones() {
        primero = nullptr;
        ultimo = nullptr;
        contador = 0;
    }

    void agregarTransaccion(string remitente, string destinatario, double monto, SHA256& sha) {
        Transaccion* nueva = new Transaccion();
        contador++;
        nueva->monto = monto;
        nueva->id = "ID" + to_string(contador);
        nueva->remitente = remitente;
        nueva->destinatario = destinatario;

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);

        char buffer[80];
        strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", &timeinfo);
        nueva->fecha = buffer;

        if (!primero) {
            primero = ultimo = nueva;
        }
        else {
            ultimo->siguiente = nueva;
            nueva->anterior = ultimo;
            ultimo = nueva;
        }

        string datos = nueva->id + remitente + destinatario + to_string(monto) + nueva->fecha;
        nueva->hash = sha.hash(datos);

        cout << "Transaccion finalizada" << endl;
        cout << "Hash de la transaccion: " << nueva->hash.substr(0, 64) << endl;
    }

    void mostrarTransacciones() {
        if (!primero) {
            cout << "No existen transacciones" << endl;
            return;
        }

        Transaccion* actual = primero;
        while (actual) {
            cout << "ID: " << actual->id << endl;
            cout << "Remitente: " << actual->remitente << endl;
            cout << "Destinatario: " << actual->destinatario << endl;
            cout << "Monto: " << actual->monto << endl;
            cout << "Fecha: " << actual->fecha;
            cout << "Hash: " << actual->hash.substr(0, 64) << endl;
            cout << "-------------------------" << endl;
            actual = actual->siguiente;
        }
    }

    void guardarTransaccionesEnArchivo(string nombreArchivo) {
        ofstream archivo(nombreArchivo);
        Transaccion* actual = primero;
        while (actual) {
            archivo << actual->id << "," << actual->remitente << "," << actual->destinatario << ","
                << actual->monto << "," << actual->fecha << "," << actual->hash << "\n";
            actual = actual->siguiente;
        }
        archivo.close();
        cout << "Transacciones guardadas en archivo." << endl;
    }

    void cargarTransaccionesDesdeArchivo(string nombreArchivo, SHA256& sha) {
        ifstream archivo(nombreArchivo);
        string linea;
        int maxID = 0;

        while (getline(archivo, linea)) {
            stringstream ss(linea);
            string id, remitente, destinatario, montoStr, fecha, hash;
            getline(ss, id, ',');
            getline(ss, remitente, ',');
            getline(ss, destinatario, ',');
            getline(ss, montoStr, ',');
            getline(ss, fecha, ',');
            getline(ss, hash);

            double monto = stod(montoStr);
            Transaccion* nueva = new Transaccion();
            nueva->id = id;
            nueva->remitente = remitente;
            nueva->destinatario = destinatario;
            nueva->monto = monto;
            nueva->fecha = fecha;
            nueva->hash = hash;

            if (id.length() > 2 && id.substr(0, 2) == "ID") {
                int idNum = stoi(id.substr(2));
                if (idNum > maxID) {
                    maxID = idNum;
                }
            }

            if (!primero) {
                primero = ultimo = nueva;
            }
            else {
                ultimo->siguiente = nueva;
                nueva->anterior = ultimo;
                ultimo = nueva;
            }
        }
        archivo.close();
         contador = maxID;
        cout << "Transacciones cargadas desde archivo." << endl;
    }


    Transaccion* buscarTransaccionPorID(string id) {
        Transaccion* actual = primero;
        while (actual) {
            if (actual->id == id)
                return actual;
            actual = actual->siguiente;
        }
        return nullptr;
    }

    void buscarTransaccionesPorUsuario(string usuario) {
        Transaccion* actual = primero;
        bool encontrado = false;
        while (actual) {
            if (actual->remitente == usuario || actual->destinatario == usuario) {
                cout << "ID: " << actual->id << endl;
                cout << "Remitente: " << actual->remitente << endl;
                cout << "Destinatario: " << actual->destinatario << endl;
                cout << "Monto: " << actual->monto << endl;
                cout << "Fecha: " << actual->fecha << endl;
                cout << "Hash: " << actual->hash.substr(0, 64) << endl;
                cout << "-------------------------" << endl;
                encontrado = true;
            }
            actual = actual->siguiente;
        }

        if (!encontrado) {
            cout << "No se encontraron transacciones para el usuario especificado." << endl;
        }
    }

};

bool autenticar() {
    string usuario, contrasena;
    cout << "=== INICIO DE SESION ===" << endl;
    cout << "Usuario: ";
    cin >> usuario;
    cout << "Contraseña: ";
    cin >> contrasena;

    if (Usuario::iniciarSesion(usuario, contrasena)) {
        cout << "Inicio de sesion exitoso." << endl;
        return true;
    }
    else {
        cout << "Usuario o contraseña incorrectos." << endl;
        return false;
    }
}

int main() {
    if (!autenticar()) {
        cout << "Acceso denegado. Saliendo del programa..." << endl;
        return 0;
    }

    int opcion;
    SHA256 sha256;
    ListaTransacciones lista;
    string nombreArchivo = "transacciones.txt";

    do {
        cout << "\n=== MENU PRINCIPAL ===" << endl;
        cout << "1. Crear transaccion" << endl;
        cout << "2. Consultar historial de transacciones" << endl;
        cout << "3. Consultar saldo" << endl;
        cout << "4. Guardar transacciones en archivo" << endl;
        cout << "5. Cargar transacciones desde archivo" << endl;
        cout << "6. Buscar transaccion por ID" << endl;
        cout << "7. Buscar transacciones por nombre de usuario" << endl;
        cout << "8. Salir" << endl;
        cout << "Seleccione una opcion: ";
        cin >> opcion;
        cin.ignore();

        switch (opcion) {
        case 1: {
            double monto;
            string destinatario;

            cout << "Remitente: " << usuarioLogeado << endl;
            cout << "Ingrese la cantidad que desea enviar: ";
            cin >> monto;
            cin.ignore();
            cout << "Escriba el nombre del destinatario: ";
            getline(cin, destinatario);

            double saldoActual = GestorSaldos::obtenerSaldo(usuarioLogeado);

            if (monto > saldoActual) {
                cout << "Saldo insuficiente. Su saldo disponible es: " << saldoActual << endl;
            }
            else if (monto <= 0) {
                cout << "Monto invalido." << endl;
            }
            else {
                lista.agregarTransaccion(usuarioLogeado, destinatario, monto, sha256);
                GestorSaldos::transferir(usuarioLogeado, destinatario, monto);
                cout << "Saldo actualizado. Nuevo saldo: " << GestorSaldos::obtenerSaldo(usuarioLogeado) << endl;
            }
            break;
        }
        case 2:
            lista.mostrarTransacciones();
            break;
        case 3:
            cout << "Su saldo actual es: " << GestorSaldos::obtenerSaldo(usuarioLogeado) << endl;
            break;
        case 4:
            lista.guardarTransaccionesEnArchivo(nombreArchivo);
            break;
        case 5:
            lista.cargarTransaccionesDesdeArchivo(nombreArchivo, sha256);
            break;
        case 6: {
            string id;
            cout << "Ingrese el ID de la transacción: ";
            getline(cin, id);
            Transaccion* encontrada = lista.buscarTransaccionPorID(id);
            if (encontrada) {
                cout << "ID: " << encontrada->id << endl;
                cout << "Remitente: " << encontrada->remitente << endl;
                cout << "Destinatario: " << encontrada->destinatario << endl;
                cout << "Monto: " << encontrada->monto << endl;
                cout << "Fecha: " << encontrada->fecha;
                cout << "Hash: " << encontrada->hash.substr(0, 64) << endl;
            }
            else {
                cout << "No se encontró una transacción con ese ID." << endl;
            }
            break;
        }
        case 7: {
            string usuario;
            cout << "Ingrese el nombre del usuario para buscar transacciones: ";
            getline(cin, usuario);
            lista.buscarTransaccionesPorUsuario(usuario);
            break;
        }
        case 8:
            cout << "Saliendo del programa..." << endl;
            break;

        default:
            cout << "Opcion no valida." << endl;
            break;
        }
    } while (opcion != 8);

    return 0;
}