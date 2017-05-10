# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-03-31 14:21
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('annotations', '0027_relationtemplate__terminal_nodes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appellation',
            name='tokenIds',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='object_node_type',
            field=models.CharField(blank=True, choices=[(b'TP', b'Open concept'), (b'CO', b'Specific concept'), (b'RE', b'Relation')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='predicate_node_type',
            field=models.CharField(blank=True, choices=[(b'TP', b'Open concept'), (b'CO', b'Specific concept'), (b'IS', b'Is/was'), (b'HA', b'Has/had')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='relationtemplatepart',
            name='source_node_type',
            field=models.CharField(blank=True, choices=[(b'TP', b'Open concept'), (b'CO', b'Specific concept'), (b'RE', b'Relation')], max_length=2, null=True),
        ),
        migrations.AlterField(
            model_name='repository',
            name='manager',
            field=models.CharField(max_length=255),
        ),
    ]