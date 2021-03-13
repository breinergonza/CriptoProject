# CriptoProject

Proyecto desarrollado en Django en el que se implementa una entidad certificadora y algunas funcionalidades para la implementación de criptografia.

## 1ro. Se restauran los componentes necesarios

```
pip install -r requirements.txt
```

## 2do. Se crea un usuario super administrador

```
python manage.py createsuperuser 
```

## 3ro. Se ejecuta el proyecto

**Local:**
```
python manage.py runserver 
```

**En el servidor:**
```
python manage.py runserver 0.0.0.0:8000
```

## Si se agrega una nueva libreria al proyecto (opcional)

Si se agrega una nueva componente o libreria al proyecto hay que ejecutar este comando para al incluirla en la librerias y no tener que instalarla de manera manual

```
pip freeze > requirements.txt
```
