import itertools
import json
import random
import string
from datetime import datetime
from operator import attrgetter, itemgetter
from typing import Union
from urllib.parse import urlparse

import jwt
from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Permission, User
from django.contrib.auth.views import LoginView, PasswordChangeView, redirect_to_login
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Max, Min
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.http.request import HttpRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.formats import date_format
from django.utils.http import is_same_domain
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _, gettext_lazy
from django.views.decorators.http import require_POST
from django.views.generic import DetailView, ListView, TemplateView
from reversion import revisions

from judge.forms import CustomAuthenticationForm, ProfileForm, newsletter_id
from judge.models import Organization, Profile, Rating, Submission
from judge.performance_points import get_pp_breakdown
from judge.ratings import rating_class, rating_progress
from judge.utils.problems import contest_completed_ids, user_completed_ids
from judge.utils.pwned import PwnedPasswordsValidator
from judge.utils.ranker import ranker
from judge.utils.subscription import Subscription
from judge.utils.unicode import utf8text
from judge.utils.views import DiggPaginatorMixin, QueryStringSortMixin, TitleMixin, generic_message
from .contests import ContestRanking

__all__ = ['UserPage', 'UserAboutPage', 'UserProblemsPage', 'users', 'edit_profile']


def remap_keys(iterable, mapping):
    return [dict((mapping.get(k, k), v) for k, v in item.items()) for item in iterable]


class UserMixin(object):
    model = Profile
    slug_field = 'user__username'
    slug_url_kwarg = 'user'
    context_object_name = 'user'

    def render_to_response(self, context, **response_kwargs):
        return super(UserMixin, self).render_to_response(context, **response_kwargs)


class UserPage(TitleMixin, UserMixin, DetailView):
    template_name = 'user/user-base.html'

    def get_object(self, queryset=None):
        if self.kwargs.get(self.slug_url_kwarg, None) is None:
            return self.request.profile
        return super(UserPage, self).get_object(queryset)

    def dispatch(self, request, *args, **kwargs):
        if self.kwargs.get(self.slug_url_kwarg, None) is None:
            if not self.request.user.is_authenticated:
                return redirect_to_login(self.request.get_full_path())
        try:
            return super(UserPage, self).dispatch(request, *args, **kwargs)
        except Http404:
            return generic_message(request, _('No such user'), _('No user handle "%s".') %
                                   self.kwargs.get(self.slug_url_kwarg, None))

    def get_title(self):
        return (_('My account') if self.request.user == self.object.user else
                _('User %s') % self.object.user.username)

    # TODO: the same code exists in problem.py, maybe move to problems.py?
    @cached_property
    def profile(self):
        if not self.request.user.is_authenticated:
            return None
        return self.request.profile

    @cached_property
    def in_contest(self):
        return self.profile is not None and self.profile.current_contest is not None

    def get_completed_problems(self):
        if self.in_contest:
            return contest_completed_ids(self.profile.current_contest)
        else:
            return user_completed_ids(self.profile) if self.profile is not None else ()

    def get_context_data(self, **kwargs):
        context = super(UserPage, self).get_context_data(**kwargs)

        context['hide_solved'] = int(self.hide_solved)
        context['authored'] = self.object.authored_problems.filter(is_public=True, is_organization_private=False) \
                                  .order_by('code')
        rating = self.object.ratings.order_by('-contest__end_time')[:1]
        context['rating'] = rating[0] if rating else None

        context['rank'] = Profile.objects.filter(
            is_unlisted=False, performance_points__gt=self.object.performance_points,
        ).count() + 1

        if rating:
            context['rating_rank'] = Profile.objects.filter(
                is_unlisted=False, rating__gt=self.object.rating,
            ).count() + 1
            context['rated_users'] = Profile.objects.filter(is_unlisted=False, rating__isnull=False).count()
        context.update(self.object.ratings.aggregate(min_rating=Min('rating'), max_rating=Max('rating'),
                                                     contests=Count('contest')))
        return context

    def get(self, request, *args, **kwargs):
        self.hide_solved = request.GET.get('hide_solved') == '1' if 'hide_solved' in request.GET else False
        return super(UserPage, self).get(request, *args, **kwargs)


class CustomLoginView(LoginView):
    template_name = 'registration/login.html'
    extra_context = {'title': _('Login')}
    authentication_form = CustomAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        password = form.cleaned_data['password']
        validator = PwnedPasswordsValidator()
        try:
            validator.validate(password)
        except ValidationError:
            self.request.session['password_pwned'] = True
        else:
            self.request.session['password_pwned'] = False
        return super().form_valid(form)


class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'registration/password_change_form.html'

    def form_valid(self, form):
        self.request.session['password_pwned'] = False
        return super().form_valid(form)


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class UserAboutPage(UserPage):
    template_name = 'user/user-about.html'

    def get_context_data(self, **kwargs):
        context = super(UserAboutPage, self).get_context_data(**kwargs)
        ratings = context['ratings'] = self.object.ratings.order_by('-contest__end_time').select_related('contest') \
            .defer('contest__description')

        context['rating_data'] = mark_safe(json.dumps([{
            'label': rating.contest.name,
            'rating': rating.rating,
            'ranking': rating.rank,
            'link': reverse('contest_ranking', args=(rating.contest.key,)),
            'timestamp': (rating.contest.end_time - EPOCH).total_seconds() * 1000,
            'date': date_format(rating.contest.end_time, _('M j, Y, G:i')),
            'class': rating_class(rating.rating),
            'height': '%.3fem' % rating_progress(rating.rating),
        } for rating in ratings]))

        if ratings:
            user_data = self.object.ratings.aggregate(Min('rating'), Max('rating'))
            global_data = Rating.objects.aggregate(Min('rating'), Max('rating'))
            min_ever, max_ever = global_data['rating__min'], global_data['rating__max']
            min_user, max_user = user_data['rating__min'], user_data['rating__max']
            delta = max_user - min_user
            ratio = (max_ever - max_user) / (max_ever - min_ever) if max_ever != min_ever else 1.0
            context['max_graph'] = max_user + ratio * delta
            context['min_graph'] = min_user + ratio * delta - delta
        return context


class UserProblemsPage(UserPage):
    template_name = 'user/user-problems.html'

    def get_context_data(self, **kwargs):
        context = super(UserProblemsPage, self).get_context_data(**kwargs)

        result = Submission.objects.filter(user=self.object, points__gt=0, problem__is_public=True,
                                           problem__is_organization_private=False) \
            .exclude(problem__in=self.get_completed_problems() if self.hide_solved else []) \
            .values('problem__id', 'problem__code', 'problem__name', 'problem__points', 'problem__group__full_name') \
            .distinct().annotate(points=Max('points')).order_by('problem__group__full_name', 'problem__code')

        def process_group(group, problems_iter):
            problems = list(problems_iter)
            points = sum(map(itemgetter('points'), problems))
            return {'name': group, 'problems': problems, 'points': points}

        context['best_submissions'] = [
            process_group(group, problems) for group, problems in itertools.groupby(
                remap_keys(result, {
                    'problem__code': 'code', 'problem__name': 'name', 'problem__points': 'total',
                    'problem__group__full_name': 'group',
                }), itemgetter('group'))
        ]
        breakdown, has_more = get_pp_breakdown(self.object, start=0, end=10)
        context['pp_breakdown'] = breakdown
        context['pp_has_more'] = has_more

        return context


class UserPerformancePointsAjax(UserProblemsPage):
    template_name = 'user/pp-table-body.html'

    def get_context_data(self, **kwargs):
        context = super(UserPerformancePointsAjax, self).get_context_data(**kwargs)
        try:
            start = int(self.request.GET.get('start', 0))
            end = int(self.request.GET.get('end', settings.DMOJ_PP_ENTRIES))
            if start < 0 or end < 0 or start > end:
                raise ValueError
        except ValueError:
            start, end = 0, 100
        breakdown, self.has_more = get_pp_breakdown(self.object, start=start, end=end)
        context['pp_breakdown'] = breakdown
        return context

    def get(self, request, *args, **kwargs):
        httpresp = super(UserPerformancePointsAjax, self).get(request, *args, **kwargs)
        httpresp.render()

        return JsonResponse({
            'results': utf8text(httpresp.content),
            'has_more': self.has_more,
        })


@login_required
def edit_profile(request):
    if request.profile.mute:
        raise Http404()
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.profile, user=request.user)
        if form.is_valid():
            with transaction.atomic(), revisions.create_revision():
                form.save()
                revisions.set_user(request.user)
                revisions.set_comment(_('Updated on site'))

            if newsletter_id is not None:
                try:
                    subscription = Subscription.objects.get(user=request.user, newsletter_id=newsletter_id)
                except Subscription.DoesNotExist:
                    if form.cleaned_data['newsletter']:
                        Subscription(user=request.user, newsletter_id=newsletter_id, subscribed=True).save()
                else:
                    if subscription.subscribed != form.cleaned_data['newsletter']:
                        subscription.update(('unsubscribe', 'subscribe')[form.cleaned_data['newsletter']])

            perm = Permission.objects.get(codename='test_site', content_type=ContentType.objects.get_for_model(Profile))
            if form.cleaned_data['test_site']:
                request.user.user_permissions.add(perm)
            else:
                request.user.user_permissions.remove(perm)

            return HttpResponseRedirect(request.path)
    else:
        form = ProfileForm(instance=request.profile, user=request.user)
        if newsletter_id is not None:
            try:
                subscription = Subscription.objects.get(user=request.user, newsletter_id=newsletter_id)
            except Subscription.DoesNotExist:
                form.fields['newsletter'].initial = False
            else:
                form.fields['newsletter'].initial = subscription.subscribed
        form.fields['test_site'].initial = request.user.has_perm('judge.test_site')

    tzmap = settings.TIMEZONE_MAP
    return render(request, 'user/edit-profile.html', {
        'require_staff_2fa': settings.DMOJ_REQUIRE_STAFF_2FA,
        'form': form, 'title': _('Edit profile'), 'profile': request.profile,
        'has_math_config': bool(settings.MATHOID_URL),
        'TIMEZONE_MAP': tzmap or 'http://momentjs.com/static/img/world.png',
        'TIMEZONE_BG': settings.TIMEZONE_BG if tzmap else '#4E7CAD',
    })


@require_POST
@login_required
def generate_api_token(request):
    profile = request.profile
    with transaction.atomic(), revisions.create_revision():
        revisions.set_user(request.user)
        revisions.set_comment(_('Generated API token for user'))
        return JsonResponse({'data': {'token': profile.generate_api_token()}})


@require_POST
@login_required
def remove_api_token(request):
    profile = request.profile
    with transaction.atomic(), revisions.create_revision():
        profile.api_token = None
        profile.save()
        revisions.set_user(request.user)
        revisions.set_comment(_('Removed API token for user'))
    return JsonResponse({})


class UserList(QueryStringSortMixin, DiggPaginatorMixin, TitleMixin, ListView):
    model = Profile
    title = gettext_lazy('Leaderboard')
    context_object_name = 'users'
    template_name = 'user/list.html'
    paginate_by = 100
    all_sorts = frozenset(('points', 'problem_count', 'rating', 'performance_points'))
    default_desc = all_sorts
    default_sort = '-performance_points'

    def get_queryset(self):
        return (Profile.objects.filter(is_unlisted=False).order_by(self.order, 'id').select_related('user')
                .only('display_rank', 'user__username', 'points', 'rating', 'performance_points',
                      'problem_count'))

    def get_context_data(self, **kwargs):
        context = super(UserList, self).get_context_data(**kwargs)
        context['users'] = ranker(
            context['users'],
            key=attrgetter('performance_points', 'problem_count'),
            rank=self.paginate_by * (context['page_obj'].number - 1),
        )
        context['first_page_href'] = '.'
        context.update(self.get_sort_context())
        context.update(self.get_sort_paginate_context())
        return context


user_list_view = UserList.as_view()


class FixedContestRanking(ContestRanking):
    contest = None

    def get_object(self, queryset=None):
        return self.contest


def users(request):
    if request.user.is_authenticated:
        participation = request.profile.current_contest
        if participation is not None:
            contest = participation.contest
            return FixedContestRanking.as_view(contest=contest)(request, contest=contest.key)
    return user_list_view(request)


def user_ranking_redirect(request):
    try:
        username = request.GET['handle']
    except KeyError:
        raise Http404()
    user = get_object_or_404(Profile, user__username=username)
    rank = Profile.objects.filter(is_unlisted=False, performance_points__gt=user.performance_points).count()
    rank += Profile.objects.filter(
        is_unlisted=False, performance_points__exact=user.performance_points, id__lt=user.id,
    ).count()
    page = rank // UserList.paginate_by
    return HttpResponseRedirect('%s%s#!%s' % (reverse('user_list'), '?page=%d' % (page + 1) if page else '', username))


class UserLogoutView(TitleMixin, TemplateView):
    template_name = 'registration/logout.html'
    title = 'You have been successfully logged out.'

    def post(self, request, *args, **kwargs):
        auth_logout(request)
        return HttpResponseRedirect(request.get_full_path())


def get_contest_redirection(decoded_jwt):
    try:
        redirect_to = decoded_jwt['redirect']
    except Exception:
        redirect_to = '/'
    return redirect_to


def verify_referer(request: HttpRequest) -> Union[Exception, bool]:
    referer = request.META.get('HTTP_REFERER')
    if referer is None:
        raise Exception('No referer')
    referer = urlparse(referer)
    if referer.scheme != 'https':
        raise Exception('Connection not secure')
    if not any(is_same_domain(referer.netloc, host) for host in settings.CSRF_TRUSTED_ORIGINS):
        raise Exception('Bad referer ' + referer.geturl())
    if request.method != 'GET':
        raise Exception('Only support GET method')
    return True


def get_email_from_schematics_token(request: HttpRequest) -> Union[str, Exception]:
    jwt_algorithm = 'HS256'
    try:
        token = request.POST['token']
    except KeyError:
        raise Exception('No token provided.')

    try:
        decoded_jwt = jwt.decode(token, settings.SCHEMATICS_JWT_SECRET, algorithms=[jwt_algorithm])
        email = decoded_jwt['email']
        if 'exp' not in decoded_jwt:
            raise Exception('Expired time required')
    except jwt.ExpiredSignatureError:
        raise Exception('Token Expired')
    except Exception as e:
        raise Exception(str(e))
    return email


def schematics_auth_login(request: HttpRequest) -> JsonResponse:
    if request.method != 'POST':
        return JsonResponse({'message': 'Only support POST method'}, status=400)

    try:
        email = get_email_from_schematics_token(request)
    except Exception as e:
        return JsonResponse({'message': str(e)}, status=403)

    try:
        user_obj = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User does not exist'}, status=400)

    auth_login(request, user_obj, backend='django.contrib.auth.backends.ModelBackend')

    return JsonResponse({'message': 'Login success as ' + user_obj.username}, status=200)


def create_or_find_school(school_name: str, school_shortname: str) -> str:
    try:
        school = Organization.objects.get(name=school_name)
        return school
    except Organization.DoesNotExist:
        zydhan = Profile.objects.get(pk=1)
        nopal = Profile.objects.get(pk=2)
        syafiq = Profile.objects.get(pk=3)
        daniel = Profile.objects.get(pk=4)
        school = Organization.objects.create(
            short_name=school_shortname,
            name=school_name,
            is_open=False,
            registrant=nopal,
        )
        school.admins.add(zydhan, nopal, syafiq, daniel)
        school.save()
        return school


def create_user_profile(user: User, school: Organization, timezone: str) -> Profile:
    profile = Profile.objects.create(math_engine="auto", user=user, timezone=timezone)
    peserta_sch_npc = Organization.objects.get(pk=2)
    profile.organizations.add(school, peserta_sch_npc)
    profile.save()

    return profile


def create_user(email: str, name: str, school_name: str,
                school_shortname: str, username: str, timezone: str) -> User:
    school = create_or_find_school(school_name, school_shortname)
    user = User.objects.create(
        email=email,
        first_name=name,
        username=username,
        password='_blank',
        is_active=True,
        is_staff=False,
        is_superuser=False,
    )
    user.set_password(''.join(random.sample(string.ascii_letters + string.digits + string.punctuation, 16)))
    user.save()
    create_user_profile(user, school, timezone)

    return user


def schematics_auth_register(request: HttpRequest) -> JsonResponse:
    try:
        verify_referer(request)
    except Exception as e:
        return JsonResponse({'message': str(e)}, status=403)

    try:
        email = request.GET['email']
        name = request.GET['name']
        school_name = request.GET['school_name']
        id_in_sch_db = request.GET['id_in_schematics_db']
        timezone = request.GET.get('timezone', 'Asia/Jakarta')
    except KeyError as e:
        return JsonResponse({'message': str(e)}, status=400)

    school_shortname = school_name
    if len(school_shortname) > 20:
        school_shortname = school_shortname[0:19]
    username = 'sch_npc_j{id_in_sch_db}_{very_first_name_lowercase}'
    username = username.format(id_in_schematics_db=id_in_sch_db, very_first_name_lowercase=name.split(' ')[0]).lower()
    create_user(email, name, school_name, school_shortname, username, timezone)
    return JsonResponse({'message': 'User registered'})
