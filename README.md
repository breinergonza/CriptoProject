# CriptoProject

Proyecto de Encripción con Django para el desarrollo de los laboratorios de Criptografia para la MCIC.

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

## Si se agrega un nuevo componente hay que ejecutar este comando (opcional)

```
pip freeze > requirements.txt
```
