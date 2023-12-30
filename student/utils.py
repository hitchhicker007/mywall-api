import os
from django.core.mail import EmailMultiAlternatives


class Util:
    @staticmethod
    def send_mail(data):
        email = EmailMultiAlternatives(
            subject=data['subject'],
            body=data['text_content'],
            from_email=os.environ.get('EMAIL_FROM'),
            to=[data['to_email']]
        )
        email.attach_alternative(data['html_content'], 'text/html')
        email.send()
