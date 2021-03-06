# -*- coding:utf-8 -*-
'''
@author: William Vedroni da Silva
@organization: S2it
@copyright: 2014 globo.com todos os direitos reservados.
'''
from rest_framework.permissions import BasePermission
from networkapi.auth import has_perm
from networkapi.admin_permission import AdminPermission


class Read(BasePermission):

    def has_permission(self, request, view):
        return has_perm(
            request.user,
            AdminPermission.VIPS_REQUEST,
            AdminPermission.READ_OPERATION
        )


class Write(BasePermission):

    def has_permission(self, request, view):
        return has_perm(
            request.user,
            AdminPermission.VIPS_REQUEST,
            AdminPermission.WRITE_OPERATION
        )
