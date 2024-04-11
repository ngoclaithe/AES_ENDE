import aes

def main():
    key = input("Nhập key: ")
    data = input("Nhập dữ liệu cần mã hóa: ")

    encrypted_data = aes.encrypt(data, key)
    print("Dữ liệu đã mã hóa:")
    print(encrypted_data)

    decrypted_data = aes.decrypt(encrypted_data, key)
    print("Dữ liệu đã giải mã:")
    print(decrypted_data)

if __name__ == "__main__":
    main()
