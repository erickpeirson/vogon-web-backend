# Generated by Django 2.2 on 2020-02-05 18:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repository', '0002_repository_repo_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='repository',
            name='url',
            field=models.CharField(default='', max_length=255),
        ),
    ]