from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from annotations import annotators
from annotations.models import Text, TextCollection, RelationSet, Appellation
from annotations.serializers import RepositorySerializer, TextSerializer, RelationSetSerializer
from repository.models import Repository
from annotations.views import utils
from django.db.models import Q

class CitesphereRepoViewSet(viewsets.ViewSet):
    queryset = Repository.objects.all()

    def retrieve(self, request, pk):
        print("entered here")
        queryset = Repository.objects.filter(repo_type=Repository.CITESPHERE)
        repository = get_object_or_404(queryset, pk=pk)

        manager = repository.manager(request.user)
        # print("manager",manager)
        groups = manager.groups()
        # print("after groups", groups)
        # print("groups value", groups)
        print("entered here in repository", repository)
        return Response({
            **RepositorySerializer(repository).data,
            'groups': groups
        })


class CitesphereGroupsViewSet(viewsets.ViewSet):
    def list(self, request, repository_pk=None):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        groups = manager.groups()
        return Response(groups)

    def retrieve(self, request, repository_pk, pk):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        collections = manager.group_collections(pk)
        items = manager.group_items(pk)

        # Append `children` field
        for collection in collections["collections"]:
            if collection["numberOfCollections"] > 0:
                collection["children"] = []

        result = {
            **collections,
            "items": items["items"]
        }

        return Response(result)


class CitesphereCollectionsViewSet(viewsets.ViewSet):
    def list(self, request, repository_pk, groups_pk):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        collections = manager.group_collections(groups_pk)
        return Response(collections)

    @action(detail=True, methods=['get'])
    def collections(self, request, repository_pk, groups_pk, pk):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        collections = manager.collection_collections(groups_pk, pk)
        for collection in collections["collections"]:
            if collection["numberOfCollections"] > 0:
                collection["children"] = []

        return Response(collections)

    @action(detail=True, methods=['get'])
    def items(self, request, repository_pk, groups_pk, pk):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        page = request.query_params.get('page', 1)
        items = manager.collection_items(groups_pk, pk, page)
        return Response(items)


class CitesphereItemsViewSet(viewsets.ViewSet):
    def list(self, request, repository_pk, groups_pk):
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        page = request.query_params.get('page', 1)
        items = manager.group_items(groups_pk, page)
        return Response(items)
    
    def retrieve(self, request, repository_pk, groups_pk, pk):
        found, project_details, part_of_project = utils._get_project_details(
            request,
            repository_pk
        )
        if not found:
            return Response({ "message": f"Project not found" }, 404)
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        item_data = manager.group_item(groups_pk, pk)
        try:
            if item_data[0] == "error":
                return Response(status=item_data[1])
        except Exception as e:
            pass
        data = item_data['item']['gilesUploads']
        result = data[2]
        master_text = None
        result_data = result['uploadedFile']
        # Text.objects.filter(uri=result_data.get('url')).delete()
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print(result_data.get('content-type'))
        # print(result_data[])
        try:
            master_text = Text.objects.get(uri=result_data.get('url'))
        except Text.DoesNotExist:
            # print("text object does not exist")
            try:
                master_text = Text.objects.create(
                    uri=result_data.get('url'),
                    title=result_data.get('filename'),
                    content_type=[result_data.get('content-type')],
                    repository_id=repository_pk,
                    addedBy=request.user
                )
            except Exception as e:
                # print("entered inside exception", e)
                pass
        submitted = False
        context = {
            'item_data': item_data,
            'master_text': TextSerializer(master_text).data if master_text else None,
            'part_of_project': part_of_project,
            'submitted': submitted,
            'project_details': project_details,
            'result': result,
            'repository': RepositorySerializer(repository).data,
        }
        return Response(context)
    
    @action(detail=True, methods=['get'], url_name='retrieve_text')
    def retrieve_text(self, request, repository_pk, groups_pk, pk):
        repository = get_object_or_404(Repository, pk=repository_pk, repo_type=Repository.CITESPHERE)
        manager = repository.manager(request.user)
        item_data = manager.group_item(groups_pk, pk)
        file_id = request.query_params.get('file_url', None)
        # Text.objects.filter(uri="https://diging.asu.edu/geco-giles-staging/rest/files/FILEu25fMNsyYvq2/content").delete()

        try:
            if item_data[0] == "error":
                return Response(status=item_data[1])
        except Exception as e:
            pass
        data = item_data['item']['gilesUploads']
        result = data[2]
        master_text = None
        for key, value in result.items():
            if key in ["uploadedFile", "extractedText"]:
                # if key == "extractedText":
                #     # print("inside extracted text jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj", value)
                if value["id"] == file_id:
                    result_data = value
                    break
                elif value['id'] == file_id:
                    result_data = value  
                    break
                
            elif key == "pages":
                for k in value:
                    # print("kkkkkkkkkkkkkkkkkkkkkkkkkkkk", k)
                    if k in ["image","text", "ocr"]:
                        for k1,v1 in k.items():
                            if v1['id'] == file_id:
                                result_data = value
                                break
                    elif k == "additionalFiles":
                        for k2 in value:
                            if k2["id"] == file_id:
                                result_data = k2  
                                break                              

        try:
            master_text = Text.objects.get(uri=result_data.get('url'))
        except Text.DoesNotExist:
            # print("text object does not exist")
            try:
                master_text = Text.objects.create(
                    uri=result_data.get('url'),
                    title=result_data.get('filename'),
                    content_type=result_data.get('content-type'),
                    repository_id=repository_pk,
                    addedBy=request.user
                )
            except Exception as e:
                # print("entered inside exception", e)
                pass

        


        #     master_resource, _ = Text.objects.get_or_create(
        #         uri=master['uri'],
        #         defaults={
        #             'title': master.get('title'),
        #             'created': master.get('created'),
        #             'repository': repository,
        #             'repository_source_id': part_of_id,
        #             'addedBy': request.user,
        #         }
        #     )
        #     resource_text_defaults.update({'part_of': master_resource})

        # resource_text, _ = Text.objects.get_or_create(
        #     uri=resource['uri'],
        #     defaults=resource_text_defaults
        # )

        project_id = self.request.query_params.get('project_id', None)

        # defaults = {
        #     'title': resource.get('title'),
        #     'created': resource.get('created'),
        #     'repository': repository,
        #     'repository_source_id': pk,
        #     'addedBy': request.user,
        #     'content_type': content_type,
        #     'part_of': resource_text,
        #     'originalResource': getattr(resource.get('url'), 'value', None),
        # }
        # text, _ = Text.objects.get_or_create(
        #     uri=content['uri'],
        #     defaults=defaults
        # )
        return Response({
            'success': True,
            'text_id': master_text.id,
            'project_id': project_id
        })
    
    @action(detail=True, methods=['get'], url_name='file')
    def get_file(self, request, repository_pk, groups_pk, pk):
        file_id = request.query_params.get('file_id', None)
        # print("file entered")
        if not file_id:
            return Response(data="file not provided", status=status.HTTP_400_BAD_REQUEST)
        repository = get_object_or_404(
            Repository,
            pk=repository_pk,
            repo_type=Repository.CITESPHERE
        )
        manager = repository.manager(request.user)
        file_content = manager.item_content(groups_pk, pk, file_id)
        try:
            if file_content[0] == "error":
                return Response(status=file_content[1])
        except Exception as e:
            pass
        # part_of_id = self.request.query_params.get('part_of', None)
        # if part_of_id:
        #     try:
        #         master = manager.resource(resource_id=int(part_of_id))
        #     except IOError:
        #         return Response({
        #             'success': False,
        #             'error': 'There was a problem communicating with the remote repository that contains'
        #                 'this content. Please go back, and try again'
        #         }, 500)

        #     master_resource, _ = Text.objects.get_or_create(
        #         uri=master['uri'],
        #         defaults={
        #             'title': master.get('title'),
        #             'created': master.get('created'),
        #             'repository': repository,
        #             'repository_source_id': part_of_id,
        #             'addedBy': request.user,
        #         }
        #     )
        #     resource_text_defaults.update({'part_of': master_resource})

        # resource_text, _ = Text.objects.get_or_create(
        #     uri=resource['uri'],
        #     defaults=resource_text_defaults
        # )

        # project_id = self.request.query_params.get('project_id', None)

        # defaults = {
        #     'title': resource.get('title'),
        #     'created': resource.get('created'),
        #     'repository': repository,
        #     'repository_source_id': pk,
        #     'addedBy': request.user,
        #     'content_type': content_type,
        #     'part_of': resource_text,
        #     'originalResource': getattr(resource.get('url'), 'value', None),
        # }
        # text, _ = Text.objects.get_or_create(
        #     uri=content['uri'],
        #     defaults=defaults
        # )
        # return Response({
        #     'success': True,
        #     'text_id': text.id,
        #     'project_id': project_id
        # })

        return Response(data=file_content, status=status.HTTP_200_OK)
    