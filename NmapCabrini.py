import nmap #Biblioteca do nmap
nn = nmap.PortScanner() #Escaneador de portas da biblioteca do nmap
portas = [1026, 1883, 1041, 8666, 27017] #Variavel para armazenar os numeros das portas do fiware
validador = 0 #Validador para o fingerprint ser ou não encontrado

ip = input("Alvo: ") #IP alvo para verificação das portas

for x in portas: #Loop que passa em todas as portas solicitadas
    varredura = nn.scan(ip, str(x)) #Transformando o numeros da portas em strings para fazer a verredura
    varredura = varredura["scan"][ip]["tcp"][int(x)]["state"] #Nesta linha é filtrando a varredura para escanear somente o TCP da porta e o estado dela
    print (f"Porta: {x} is {varredura}") #Aqui vai ser printado as portas e o resultado da varredura
    if x == 1026 and varredura == "open":
        validador += 1                      #Nestas sequencias cada porta aberta vai somar +1 no validador para aprovar o fingerprint
        
    elif x == 1883 and varredura == "open":
        validador += 1
        
    elif x == 1041 and varredura == "open":
        validador += 1
        
    elif x == 8666 and varredura == "open":
        validador += 1
        
    elif x == 27017 and varredura == "open":
        validador += 1

if validador == 5:                      #Caso a soma de todas as portas seje igual a 5, significa que todas as portas estão abertas e o fingerprint é encontrado
    print (f"Fingerprint encontrado")

else:                                   #Caso a soma seje menor que 5 o resultado do fingerprint é "não encontrado"
    print (f"Fingerprint não encontrado")