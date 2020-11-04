import Crypto
import binascii
import os 

from Crypto import Random

from django.conf import settings
from django.http import request,HttpResponse, Http404
from django.shortcuts import HttpResponseRedirect, render, HttpResponse, redirect

from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

from io import open
from Crypto.Random import get_random_bytes

from .forms import UploadFileForm

# Create your views here.
from cifradoapp.models import Account
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token

from cifradoapp.api.serializer import RegistrationSerializer

from rest_framework.views import APIView

from rest_framework.permissions import IsAuthenticated

class HelloView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)

@api_view(['POST',])
def register_view(request):
    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            account = serializer.save()
            data['response'] = "successfully a new user."
            data['email'] = account.email
            data['username'] = account.username
            # token = Token.objects.create(user=account)
            # print(token.key)
        else:
            data = serializer.errors
        return Response(data)

def index(request):

    #Se genera un numero random
    ramdom_gen = Crypto.Random.new().read

    #Se genera una llave privada
    private_key = RSA.generate(2048, ramdom_gen)

    #Generamos una llave publica
    public_key = private_key.publickey()

    #Convertimos las llaves en utf8 para poder leerlas y mostrarlas
    private_key = private_key.exportKey(format='DER')
    public_key = public_key.exportKey(format='DER')

    #Se genera el archivo con la llave privada
    file_out = open("./cifradoapp/cifrado/keys/private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    #Se genera el archivo con la llave publica
    file_out = open("./cifradoapp/cifrado/keys/public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    private_key = binascii.hexlify(private_key).decode('utf8')
    public_key = binascii.hexlify(public_key).decode('utf8')

    llave_privada = private_key
    llave_publica = public_key

    #Se realiza el proceso inverso para utilizarlas en el cifrado
    private_key = RSA.importKey(binascii.unhexlify(private_key))
    public_key = RSA.importKey(binascii.unhexlify(public_key))

    #Se cargan los datos del archivo
    archivo = open("./cifradoapp/cifrado/archivos/ejemplo.txt", "r")

    #Se lee el archivo con los datos a encriptar
    datosArchivo = archivo.read()

    #Se codifica el mensaje
    data = datosArchivo.encode("utf-8")

    #Ciframos el texto el mensaje con la llave publica
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encripted_msg = cipher_rsa.encrypt(data)

    print('************** Mensaje Encriptado **************')
    print(encripted_msg)
    print('************************************************')

    #Desencriptamos el mensaje con la llave privada
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decripted_msg = cipher_rsa.decrypt(encripted_msg).decode('utf-8') 

    print('************** Mensaje Desencriptado **************')
    print(decripted_msg)
    print('************************************************')

    return render(request, 'index.html', {
        'data_cifrar': datosArchivo,
        'key_private':llave_privada,
        'key_public':llave_publica,
        'data_encrypt':encripted_msg,
        'data_decript':decripted_msg    
    })

def file_text(request):

    filename = "./cifradoapp/cifrado/archivos/ejemplo.txt"
    data = open(filename, "rb").read()
    response = HttpResponse(data, content_type="text/plain")
    response["Content-Length"] = os.path.getsize(filename)
    
    return response

def file_public(request):

    filename = "./cifradoapp/cifrado/keys/public.pem"
    data = open(filename, "rb").read()
    response = HttpResponse(data, content_type="application/x-pem-file")
    response["Content-Length"] = os.path.getsize(filename)
    response["Content-Disposition"] = 'attachment; filename="public_key.pem"'
    
    return response

def file_private(request):

    filename = "./cifradoapp/cifrado/keys/private.pem"
    data = open(filename, "rb").read()
    response = HttpResponse(data, content_type="application/x-pem-file")
    response["Content-Length"] = os.path.getsize(filename)
    response["Content-Disposition"] = 'attachment; filename="private_key.pem"'
    
    return response

def save_file(request):

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        handle_uploaded_file(request.FILES['file_txt'])

    return HttpResponseRedirect('/index/')

def handle_uploaded_file(f):    
    with open('./cifradoapp/cifrado/archivos/ejemplo.txt', 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)

def download(request, path):
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404


    """Codificacion
        Metodo que permite cifrar información
    Returns:
        json: message
    """
class CodeText(APIView):
    # permission_classes = (IsAuthenticated,)
    def post(self, request):

        info=request.data

        msgCifrar = info['msg']

        print(msgCifrar)        
    
        # Sign a message
        message = msgCifrar        

        hash_obj = SHA256.new(message.encode("utf8"))

        # Se lee la llave privada
        key = DSA.import_key(open("./cifradoapp/cifrado/keys/der/private_key_dsa.pem").read())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        dts = binascii.hexlify(signature).decode('utf8')

        print(dts)
    
        # Load the public key
        f = open("./cifradoapp/cifrado/keys/der/public_key_dsa.pem", "r")

        hash_obj = SHA256.new(message.encode("utf8"))
        
        pub_key = DSA.import_key(f.read())

        verifier = DSS.new(pub_key, 'fips-186-3')
    
        # Verify the authenticity of the message
        try:
            verifier.verify(hash_obj, signature)
            print("The message is authentic.")
        except ValueError:
            print ("The message is not authentic.")

        # print(signature)

        data = {
            "original": info['msg'],
            "code": dts
        }

        return Response(data)



# def cifrado(request):

#     #Se genera un numero random
#     ramdom_gen = Crypto.Random.new().read

#     #Se genera una llave privada
#     private_key = RSA.generate(2048, ramdom_gen)

#     #Generamos una llave publica
#     public_key = private_key.publickey()

#     #Convertimos las llaves en utf8 para poder leerlas y mostrarlas
#     private_key = private_key.exportKey(format='DER')
#     public_key = public_key.exportKey(format='DER')

#     #Se genera el archivo con la llave privada
#     file_out = open("./cifradoapp/cifrado/keys/der/private.der", "wb")
#     file_out.write(private_key)
#     file_out.close()

#     #Se genera el archivo con la llave publica
#     file_out = open("./cifradoapp/cifrado/keys/der/public.der", "wb")
#     file_out.write(public_key)
#     file_out.close()

#     private_key = binascii.hexlify(private_key).decode('utf8')
#     public_key = binascii.hexlify(public_key).decode('utf8')

#     llave_privada = private_key
#     llave_publica = public_key

#     #Se realiza el proceso inverso para utilizarlas en el cifrado
#     private_key = RSA.importKey(binascii.unhexlify(private_key))
#     public_key = RSA.importKey(binascii.unhexlify(public_key))

#     #Se cargan los datos del archivo
#     archivo = open("./cifradoapp/cifrado/archivos/ejemplo.txt", "r")

#     #Se lee el archivo con los datos a encriptar
#     datosArchivo = archivo.read()

#     #Se codifica el mensaje
#     data = datosArchivo.encode("utf-8")

#     #Ciframos el texto el mensaje con la llave publica
#     cipher_rsa = PKCS1_OAEP.new(public_key)
#     encripted_msg = cipher_rsa.encrypt(data)

#     print('************** Mensaje Encriptado **************')
#     print(encripted_msg)
#     print('************************************************')

#     #Desencriptamos el mensaje con la llave privada
#     cipher_rsa = PKCS1_OAEP.new(private_key)
#     decripted_msg = cipher_rsa.decrypt(encripted_msg).decode('utf-8') 

#     print('************** Mensaje Desencriptado **************')
#     print(decripted_msg)
#     print('************************************************')

#     return render(request, 'index.html', {
#         'data_cifrar': datosArchivo,
#         'key_private':llave_privada,
#         'key_public':llave_publica,
#         'data_encrypt':encripted_msg,
#         'data_decript':decripted_msg    
#     })


class DeCodeText(APIView):
    # permission_classes = (IsAuthenticated,)
    def post(self, request):

        info=request.data

        msgDesCifrar = info['msg']

        
        key = RSA.importKey(open('./cifradoapp/cifrado/keys/der/private_key_dsa.').read())
    
        dsize = SHA.digest_size

        sentinel = Random.new().read(16+dsize)      # Let's assume that average data length is 15
    
        cipher = PKCS1_v1_5.new(key)
        message = cipher.decrypt(ciphertext, sentinel)
    
        digest = SHA.new(message[:-dsize]).digest()
        if digest==message[-dsize:]:                # Note how we DO NOT look for the sentinel
            print("Encryption was correct.")
        else:
            print("Encryption was not correct.")


        # Se lee la llave privada
        key = DSA.import_key(open("./cifradoapp/cifrado/keys/der/private_key_dsa.pem").read())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        dts = binascii.hexlify(signature).decode('utf8')

        print(dts)
    
        # Load the public key
        f = open("./cifradoapp/cifrado/keys/der/public_key_dsa.pem", "r")

        hash_obj = SHA256.new(message.encode("utf8"))
        
        pub_key = DSA.import_key(f.read())

        verifier = DSS.new(pub_key, 'fips-186-3')
    
        # Verify the authenticity of the message
        try:
            verifier.verify(hash_obj, signature)
            print("The message is authentic.")
        except ValueError:
            print ("The message is not authentic.")

        # print(signature)

        data = {
            "original": info['msg'],
            "code": dts
        }

        return Response(data)




class GenerateKeysDsa(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):

        # Create a new DSA key
        private_key = DSA.generate(2048)
        key = private_key
        public_key = private_key.publickey()

        #Convertimos las llaves en utf8 para poder leerlas y mostrarlas
        private_key = private_key.exportKey(format='PEM')
        public_key = public_key.exportKey(format='PEM')

        #Se genera el archivo con la llave privada
        file_out = open("./cifradoapp/cifrado/keys/der/private_key_dsa.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        #Se genera el archivo con la llave publica
        file_out = open("./cifradoapp/cifrado/keys/der/public_key_dsa.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        content = {'sucess': True, 'message': 'Llaves generadas con exito'}
        return Response(content)