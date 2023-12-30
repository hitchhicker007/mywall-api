from django.urls import path
from universities.views import GetUniversitiesView

urlpatterns = [
    path('list/', GetUniversitiesView.as_view(), name='list-universities'),
    path('add/', GetUniversitiesView.as_view(), name='add-university'),
]