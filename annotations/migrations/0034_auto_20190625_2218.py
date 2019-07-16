# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-06-25 22:18
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('annotations', '0033_relationtemplate_use_in_mass_assignment'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='relationtemplate',
            name='use_in_mass_assignment',
        ),
        migrations.AlterField(
            model_name='appellation',
            name='controlling_verb',
            field=models.CharField(blank=True, choices=[(None, ''), ('is', 'is/was'), ('has', 'has/had')], max_length=4, null=True),
        ),
        migrations.AlterField(
            model_name='documentposition',
            name='position_type',
            field=models.CharField(choices=[('TI', 'Token IDs'), ('BB', 'Bounding box'), ('XP', 'XPath'), ('CO', 'Character offsets'), ('WD', 'Whole document')], max_length=2),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='object_node_type',
            field=models.CharField(blank=True, choices=[('TP', 'Open concept'), ('CO', 'Specific concept'), ('DT', 'Date appellation'), ('RE', 'Relation')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='predicate_node_type',
            field=models.CharField(blank=True, choices=[('TP', 'Open concept'), ('CO', 'Specific concept'), ('IS', 'Is/was'), ('HA', 'Has/had')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='source_node_type',
            field=models.CharField(blank=True, choices=[('TP', 'Open concept'), ('CO', 'Specific concept'), ('DT', 'Date appellation'), ('RE', 'Relation')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='text',
            name='created',
            field=models.DateField(blank=True, help_text='The publication or creation date of the original document.', null=True),
        ),
        migrations.AlterField(
            model_name='text',
            name='document_type',
            field=models.CharField(blank=True, choices=[('PT', 'Plain text'), ('IM', 'Image'), ('HP', 'Hypertext')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='text',
            name='title',
            field=models.CharField(help_text='The original title of the document.', max_length=1000),
        ),
        migrations.AlterField(
            model_name='text',
            name='uri',
            field=models.CharField(help_text='Uniform Resource Identifier. This should be sufficient to retrieve text from a repository.', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='textcollection',
            name='quadriga_id',
            field=models.CharField(blank=True, help_text='Use this field to specify the ID of an existing project in Quadriga with which this project should be associated.', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='affiliation',
            field=models.CharField(blank=True, help_text='Your home institution or employer.', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='conceptpower_uri',
            field=models.URLField(blank=True, help_text='Advanced: if you have an entry for yourself in the Conceptpower authority service, please enter it here.', max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='email',
            field=models.EmailField(max_length=255, verbose_name='email address'),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='imagefile',
            field=models.URLField(blank=True, help_text='Upload a profile picture.', null=True),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='is_active',
            field=models.BooleanField(default=True, help_text='Un-set this field to deactivate a user. This is extremely preferable to deletion.'),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='link',
            field=models.URLField(blank=True, help_text='The location of your online bio or homepage.', max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='vogonuser',
            name='location',
            field=models.CharField(blank=True, help_text='Your current geographical location.', max_length=255, null=True),
        ),
    ]