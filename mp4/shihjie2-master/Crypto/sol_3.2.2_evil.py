#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           �zW��P �#F���`�%�[1C�<Z{�ċ��������~��eD��Ú._R�x��&�����C
�[�Yր�"��T��5X�̜n��O_�A*���t��)�o�3��"�������
��CQ9}"""
from hashlib import sha256

if sha256(blob).hexdigest()=="e4c6ab735143e850c8b6f9e138879a7f6fb60c750017377361b3030a36d7cef4":
	print "Prepare to be destroyed!"
elif  sha256(blob).hexdigest()=="217d749ea87b702732d6383ae4e3c9e92f3846c65bf714e32c244e948dd5ba8e":
	print "I come in peace."
else:
	print "failed"
