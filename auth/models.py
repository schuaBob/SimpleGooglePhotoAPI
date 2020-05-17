from django.db import models

class User(models.Model):
    userId = models.CharField(max_length=100,blank=False,unique=True)
    accessToken= models.CharField(max_length=2048,blank=False)
    # refreshTime=models.DateTimeField(auto_now_add=True,blank=False)
    expiresIn = models.IntegerField()
    refreshToken=models.CharField(max_length=512,blank=False)
    lastUpdateTime=models.DateTimeField(auto_now=True,blank=False)

    
