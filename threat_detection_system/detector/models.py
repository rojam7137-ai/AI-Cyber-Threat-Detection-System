from django.db import models

class TrafficLog(models.Model):

    duration = models.IntegerField()
    src_bytes = models.IntegerField()
    dst_bytes = models.IntegerField()
    protocol = models.IntegerField()

    result = models.CharField(max_length=100)

    ai_analysis = models.TextField(blank=True, null=True)

    attacker_ip = models.CharField(max_length=50, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.result