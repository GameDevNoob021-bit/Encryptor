import os
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Função para gerar uma chave de 256 bits
def gerar_chave():
    return os.urandom(32)  # 32 bytes = 256 bits

# Função para criptografar um arquivo
def criptografar_arquivo(nome_arquivo, chave):
    iv = os.urandom(16)  # Gera um vetor de inicialização aleatório
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(nome_arquivo, "rb") as arquivo:
        dados = arquivo.read()
    
    # Prepara os dados para criptografia
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    dados_padded = padder.update(dados) + padder.finalize()
    
    dados_criptografados = encryptor.update(dados_padded) + encryptor.finalize()

    # Salva o arquivo criptografado junto com o IV (vetor de inicialização)
    with open(nome_arquivo + ".enc", "wb") as arquivo_enc:
        arquivo_enc.write(iv)  # Salva o IV no início do arquivo
        arquivo_enc.write(dados_criptografados)

    messagebox.showinfo("Sucesso", f"{nome_arquivo} foi criptografado com sucesso!")

# Função para descriptografar um arquivo
def descriptografar_arquivo(nome_arquivo, chave):
    with open(nome_arquivo, "rb") as arquivo_enc:
        iv = arquivo_enc.read(16)  # Lê o IV do início do arquivo
        dados_criptografados = arquivo_enc.read()
    
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descriptografa os dados
    dados_padded = decryptor.update(dados_criptografados) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    dados = unpadder.update(dados_padded) + unpadder.finalize()

    # Salva o arquivo descriptografado
    with open(nome_arquivo[:-4], "wb") as arquivo_dec:
        arquivo_dec.write(dados)

    messagebox.showinfo("Sucesso", f"{nome_arquivo} foi descriptografado com sucesso!")

# Função para abrir o diálogo de seleção de arquivos
def selecionar_arquivo():
    nome_arquivo = filedialog.askopenfilename()
    return nome_arquivo

# Função chamada quando o botão de criptografar é pressionado
def criptografar():
    nome_arquivo = selecionar_arquivo()
    if nome_arquivo:
        chave = gerar_chave()  # Gera uma nova chave para cada criptografia
        chave_hex = chave.hex()
        campo_chave.delete(0, END)  # Limpa o campo antes de inserir a nova chave
        campo_chave.insert(0, chave_hex)  # Insere a chave no campo
        criptografar_arquivo(nome_arquivo, chave)

# Função chamada quando o botão de descriptografar é pressionado
def descriptografar():
    nome_arquivo = selecionar_arquivo()
    if nome_arquivo:
        chave_input = campo_chave.get()  # Obtém a chave do campo de entrada
        if chave_input:
            try:
                chave = bytes.fromhex(chave_input)
                if len(chave) != 32:
                    raise ValueError("A chave deve ter 32 bytes (256 bits).")
                descriptografar_arquivo(nome_arquivo, chave)
            except Exception as e:
                messagebox.showerror("Erro", str(e))

# Função para salvar a chave em um arquivo
def salvar_chave():
    chave_hex = campo_chave.get()
    if not chave_hex:
        messagebox.showwarning("Aviso", "Nenhuma chave para salvar.")
        return
    
    caminho = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Arquivo de Chave", "*.key")])
    
    if caminho:
        with open(caminho, "w") as f:
            f.write(chave_hex)
            messagebox.showinfo("Sucesso", "Chave salva com sucesso!")

# Função para importar uma chave de um arquivo
def importar_chave():
    caminho = filedialog.askopenfilename(filetypes=[("Arquivo de Chave", "*.key")])
    
    if caminho:
        with open(caminho, "r") as f:
            chave_hex = f.read().strip()
            if len(bytes.fromhex(chave_hex)) != 32:
                messagebox.showerror("Erro", "O arquivo da chave deve conter exatamente 32 bytes.")
            else:
                campo_chave.delete(0, END)
                campo_chave.insert(0, chave_hex)
                messagebox.showinfo("Sucesso", "Chave importada com sucesso!")

# Configuração da janela principal
janela = Tk()
janela.title("Criptografia de Arquivos - AES-256")

# Aplicando tema escuro
janela.configure(bg="#2E2E2E")
Label(janela, text="Chave (hex):", bg="#2E2E2E", fg="white").pack(pady=5)
campo_chave = Entry(janela, width=64)
campo_chave.pack(pady=5)

# Botões para criptografar e descriptografar
botao_criptografar = Button(janela, text="Criptografar Arquivo", command=criptografar)
botao_criptografar.pack(pady=10)

botao_descriptografar = Button(janela, text="Descriptografar Arquivo", command=descriptografar)
botao_descriptografar.pack(pady=10)

botao_salvar_chave = Button(janela, text="Salvar Chave", command=salvar_chave)
botao_salvar_chave.pack(pady=5)

botao_importar_chave = Button(janela, text="Importar Chave", command=importar_chave)
botao_importar_chave.pack(pady=5)

# Executa o loop principal da interface gráfica
janela.mainloop()