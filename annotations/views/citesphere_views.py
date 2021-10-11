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
        # print("entered here")
        queryset = Repository.objects.filter(repo_type=Repository.CITESPHERE)
        repository = get_object_or_404(queryset, pk=pk)

        manager = repository.manager(request.user)
        # print("manager",manager)
        groups = manager.groups()
        # print("after groups", groups)
        # print("groups value", groups)
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
        # try:
        #     item_data['item']['gilesUploads']
        #     print(item_data['item']['gilesUploads'])
        # except Exception as e:
        #     print("exception", Exception)
        #     return Response(data=item_data)
        data = item_data['item']['gilesUploads']
        result = data[2]
        # print("result",result)
        # handle list length > 0
        # print(result_data)
        # result = result_data.'uploadedFile')
        master_text = None
        result_data = result['uploadedFile']
        try:
            # import pdb; pdb.set_trace()
            # result['content_types'] = [result['content-type']]
            master_text = Text.objects.get(uri=result_data.get('url'))
        except Text.DoesNotExist:
            # print("exception")
            print("text object does not exist")
            try:
                master_text = Text.objects.create(
                    uri=result_data.get('url'),
                    title=result_data.get('filename'),
                    # public=result.get('public'),
                    content_type=[result_data.get('content_type')],
                    repository_id=repository_pk,
                    addedBy=request.user
                )
                    # print("master_text", master_text)
            except Exception as e:
                print("entered inside exception", e)
                pass
        # aggregate_content = result.get('aggregate_content')
        # print(master_text_objects)
        # print(final_result)
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
        # print(context['result'])
        # print("final_resulttttttttt", final_result)
        # print('master text objects', master_text_objects)
        return Response(context)
    
    @action(detail=True, methods=['get'], url_name='file')
    def get_file(self, request, repository_pk, groups_pk, pk):
        file_id = request.query_params.get('file_id', None)
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
        return Response(data=file_content, status=status.HTTP_200_OK)
    