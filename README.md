# Sensitive File Finder

## Deskripsi

Sensitive File Finder adalah sebuah tools yang dibuat dengan Go untuk mendeteksi atau mencari file sensitif dari daftar website. Tools ini membaca daftar target dari file, kemudian melakukan pencarian berdasarkan referensi dalam `lib/sensitive.json`.

## Struktur Project

```
SensitiveFileFinder/
│── main.go
│── lib/
│   └── sensitive.json
```

- **main.go** → File utama yang menjalankan proses scanning.
- **lib/sensitive.json** → Database referensi yang berisi daftar file sensitif yang umum ditemukan di website.

## Fitur

- Menerima daftar target dari file.
- Mencari file sensitif berdasarkan referensi dalam `sensitive.json`.
- Menggunakan multi-threading untuk kecepatan tinggi.
- Menyimpan hasil pencarian secara real-time.

## Instalasi & Penggunaan

### 1. Clone Repository

```bash
git clone https://github.com/maw3six/Sensi.git
cd Sensi
```

### 2. Compile & Jalankan

```bash
go build -o sensi main.go
./sensi
```

### 3. Format File `sensitive.json`

File ini berisi daftar path file sensitif yang akan dicari, contoh:

```json
{
  "Sensitive" : [
{
 "path" : "/test.txt",
  "content" : "#application/json#text/html#image",
  "lentgh" : "*"

} ,
  {
    "path" : "/access.log",
    "content" : "#application/json#text/html#image",
    "lentgh" : "*"
  }
    ,
```

### 4. Input File Daftar Target

File daftar target berisi satu URL per baris, contoh `list.txt`:

```
https://example.com
https://targetsite.com
```

## Output

Hasil pencarian akan disimpan secara real-time.

## Lisensi

MIT License

---

Dikembangkan oleh **[@maw3six]**
