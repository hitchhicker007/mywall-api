from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework import filters

from universities.models import University
from universities.serializers import UniversitySerializer
from universities.pagination import BasicPagination


class GetUniversitiesView(ListAPIView):
    pagination_class = BasicPagination
    serializer_class = UniversitySerializer
    filter_backends = (filters.SearchFilter,)
    search_fields = ['name']


class AddUniversityView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            uni_name = request.data.get('name')
            # book = Book.objects.get(pk=book_id)
            University.objects.create(name=uni_name)
            return Response({"message": "University added successfully."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"message": "something went wrong."}, status=status.HTTP_400_BAD_REQUEST)
