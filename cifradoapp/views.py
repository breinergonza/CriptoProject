import Crypto
import binascii
import os 
import requests

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

        """Registro de usuarios via POST

        Raises:
            Http404: [description]

        Returns:
            [type]: [description]
        """
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
        else:
            data = serializer.errors
        return Response(data)

    """Pagina inicial
    """
def index(request):
    return render(request, 'index.html', {})


def encript_rsa(request):

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

    return render(request, 'encriptRsa.html', {
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
        handle_uploaded_file(request.FILES['file_txt'], "ejemplo.txt")

    return HttpResponseRedirect('/index/')

    """
    Metodo para cargar una archivo de texto
    """
def handle_uploaded_file(f):
    nom = binascii.hexlify(get_random_bytes(4)).decode('utf8')
    print(nom)
    with open(f'./cifradoapp/cifrado/archivos/{nom}.txt', 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)

def handle_uploaded_file_api(f):
    nom = binascii.hexlify(get_random_bytes(4)).decode('utf8')
    print(nom)
    file = f'./cifradoapp/cifrado/archivos/{nom}.txt'
    with open(file, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return file

def download(request, path):
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404


"""Codificacion
    Metodo que permite firmar la información
Returns:
    json: message
"""
class CodeText(APIView):
    # permission_classes = (IsAuthenticated,)
    def post(self, request):

        info=request.data

        nombreCertificado = info['nombreCertificado']
        apellido = info['apellido']
        nombre = info['nombre']
        id_clave = info['idClave']
        pin = info['pin']

        form = UploadFileForm(request.POST, request.FILES)
        fil = handle_uploaded_file_api(request.FILES['file_txt'])

        print("Archivo : " + fil)              

        # Mensaje a crifrar
        msgArchivo = open(fil, "r")
        msgCifrar = msgArchivo.read()
        message = msgCifrar        

        # Se genera el hash del texto
        hash_obj = SHA256.new(message.encode("utf8"))

        # Se lee la llave privada
        key = DSA.import_key(open("./cifradoapp/cifrado/keys/der/private_key_dsa.pem").read())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        dts = binascii.hexlify(signature).decode('utf8')

        print(dts)
    
        # Se lee la llave publica
        f = open("./cifradoapp/cifrado/keys/der/public_key_dsa.pem", "r")
        hash_obj = SHA256.new(message.encode("utf8"))        
        pub_key = DSA.import_key(f.read())

        verifier = DSS.new(pub_key, 'fips-186-3')

        msgSalida = f'Firma Digital: { signature }      Longitud de la firma: 368      Algoritmo: RSA      Función Hash: SHA-256       Clave: [{apellido}][{nombre}][DSA-1024][{pin}]       Mensaje: {message}'

        print(msgSalida)

        #Se genera el archivo con la llave privada
        nomArchivo = binascii.hexlify(get_random_bytes(4)).decode('utf8')        
        signa_file_out = open(f'./cifradoapp/cifrado/archivos_firmados/{nomArchivo}.hex', "wb")
        signa_file_out.write(str.encode(msgSalida))
        signa_file_out.close()

        # Se valida la autenticidad de la firma
        try:
            verifier.verify(hash_obj, signature)
            print("El mesaje generado fue validado.")
        except ValueError:
            print ("El mensaje generado no pudo ser validado.")

        data = {
            "original": message,
            "firma": dts,
            "codigo_archivo": nomArchivo
        }

        return Response(data)

class DeCodeText(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):        

        info=request.data       

        msgDesCifrar = info['original']
        msgCodificado = info['firma']
        msgResp = ""
        success = False

        print("Mensaje a validar: " + msgDesCifrar)
        signature = bytes.fromhex(msgCodificado)

        key = DSA.import_key(open('./cifradoapp/cifrado/keys/der/public_key_dsa.pem').read())
        h = SHA256.new(msgDesCifrar.encode("utf8"))
        verifier = DSS.new(key, 'fips-186-3')
        
        try:
            verifier.verify(h, signature)
            success = True
            msgResp = "The message is authentic... Yey!!"
            print(msgResp)
        except ValueError:
            msgResp = "The message is not authentic... :( "
            print (msgResp)

        data = {
            "success": success,
            "result": msgResp
        }

        return Response(data)


"""
    Metodo que permite actualizar
    y regenerar las llav es publica y privada
Returns:
    [type]: [description]
"""
class GenerateKeysDsa(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):

        # Generamos la sal
        salt = get_random_bytes(16)

        # Create a new DSA key
        private_key = DSA.generate(2048)
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

        llave_privada = binascii.hexlify(private_key).decode('utf8') 
        llave_publica = binascii.hexlify(public_key).decode('utf8')

        content = {
            'sucess': True, 
            'message': 'Llaves generadas con exito',
            'data': {
                'public_key': llave_publica,
                'private_key':llave_privada
            }}

        return Response(content)

"""API que devuelve un archivo de texto cifrado

Returns:
    [type]: [text/plain]
"""
class SendFile(APIView):
    def get(self, request):
        
        archivo = self.request.query_params.get('file', None)

        if archivo is not None:
            file_path = f'./cifradoapp/cifrado/archivos_firmados/{archivo}.hex'

            with open(file_path, 'r') as file:
                response = HttpResponse(file, content_type='text/plain')
                response['Content-Disposition'] = f'attachment; filename={archivo}.hex'
                return response

        return {'success': False, 'msg': 'Archivo no encontrado'}        


class ValidateTempratureText(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):        

        info=request.data       

        minuto = info['minuto']
        msgDesCifrar = info['temperatura']
        msgCodificado = info['firma']

        print(minuto)
        print(msgDesCifrar)
        print(msgCodificado)

        msgResp = ""
        success = False

        print("Temperatura a validar: " + msgDesCifrar)
        signature = bytes.fromhex(msgCodificado)

        key = DSA.import_key(open('./cifradoapp/cifrado/keys/der/public_key_dsa.pem').read())
        h = SHA256.new(msgDesCifrar.encode("utf8"))
        verifier = DSS.new(key, 'fips-186-3')
        
        try:
            verifier.verify(h, signature)
            success = True
            msgResp = "The message is authentic... Yey!!"
            print(msgResp)

            urlGrafica = "http://52.23.188.230:5000/grafica"
            headersGrafica = { 
                    'Content-Type': 'application/x-www-form-urlencoded' 
            }

            if minuto == "min_5":   
                payloadGrafica=f'minuto=min_5&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto=min_15&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto=min_25&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto=min_35&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto=min_45&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto=min_55&temperatura=0'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                payloadGrafica=f'minuto={minuto}&temperatura={float(msgDesCifrar)}'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)

                print(response.text) 
            
            else:
                payloadGrafica=f'minuto={minuto}&temperatura={float(msgDesCifrar)}'                
                response = requests.request("POST", urlGrafica, headers=headersGrafica, data=payloadGrafica)
                print(response.text)            
            

        except ValueError:
            msgResp = "The message is not authentic... :( "
            print (msgResp)

        data = {
            "success": success,
            "result": msgResp
        }

        return Response(data)