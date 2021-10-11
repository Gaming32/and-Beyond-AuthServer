from datetime import datetime, timezone

from django.core.management.base import BaseCommand
from sessions.models import Session


class Command(BaseCommand):
    help = 'Removes all expired sessions from the database'

    def handle(self, *args, **options) -> None:
        to_delete = Session.objects.filter(expiry__lte=datetime.now(timezone.utc))
        count, _ = to_delete.delete()
        self.stdout.write(f'Successfully removed {count} expired session(s) from the database.')
