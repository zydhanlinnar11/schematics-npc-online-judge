# Dokumentasi SSO

## Prasyarat

- Terdapat perjanjian `jwt_secret` pada [services.yaml](./webapp/config/services.yaml)
- Perjanjian path otentikasi dari schematics
- JWT dengan struktur sebagai berikut:

Header:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload:

```json
{
  "username": "...",
  "exp": "..."
}
```

`username` berupa username yang didaftarkan melalui API POST `/api/v4/users` [(Baca dokumentasi)](https://www.domjudge.org/demoweb/api/doc). `exp` diusahakan expired dalam waktu yang cukup singkat sehingga token seolah-olah bersifat *single-use*.

## Metode login

Menggunakan AJAX/Fetch pada client-side JavaScript. Beri delay beberapa detik untuk proses autentikasi sebelum dilakukan redirect ke online judge Schematics NPC Senior.

## Langkah-langkah

- Asumsikan DOMJudge diletakkan pada `https://schematics.its.ac.id/my/sch-npc/senior`

- Asumsikan ingin melakukan redirect ke `https://schematics.its.ac.id/my/sch-npc/senior/public` (Public DOMJudge)

- Siapkan JWT token dengan ketentuan seperti di atas

- Lakukan autentikasi terlebih dahulu pada client-side dengan mengirim POST dengan content berupa `application/x-www-form-urlencoded` ke `https://schematics.its.ac.id/my/sch-npc/senior/schematics/callback`. Pada body, kirim key bernama `token` berisikan JWT.

Contoh script:

```js
const xhr = new XMLHttpRequest();

xhr.onreadystatechange = () => {
    if (xhr.status != 200) {
        console.error("Login gagal"); // Anggap saja ini UI XD
        return;
    }
    console.log("Login success") // Anggap saja ini UI XD
    window.open(
        "http://schematics.its.ac.id/my/sch-npc/senior/public",
        "_self"
    )
};

function redirectToSchematics() {
    console.log("Mengarahkan ke Schematics NPC Senior") // Anggap saja ini UI XD
    xhr.open(
        "POST",
        "http://schematics.its.ac.id/my/sch-npc/senior/schematics/callback"
    )
    const token = 'MASUKKAN_TOKEN'
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
    xhr.send(`token=${token}`)
}
```

Have a nice day :)
