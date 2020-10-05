from django.db import models

# Create your models here.

class DatosEncript(models.Model):
    archivo = models.FileField(default='null', upload_to="archivos")