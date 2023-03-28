import discord
import requests
import uuid
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from models import DeliverooUser
from discord.ext import commands
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from discord import app_commands, Interaction, Object
from config import deliveroo_db_url
from utils import id_generator


class Deliveroo(commands.GroupCog, name="deliveroo"):
    def __init__(self, bot):
        self.bot = bot
        engine = create_engine(deliveroo_db_url, echo=False)
        self.session = sessionmaker(bind=engine)()
        super().__init__()

    class Cache:
        def __init__(self, auth, mfa, cookies, uid):
            self.auth = auth
            self.mfa = mfa
            self.cookies = cookies
            self.uid = uid

    cache = {}

    base_headers = {
        "Accept-Language": "en-UK",
        "User-Agent": f"Deliveroo/3.109.0 (samsung SM-G935F;Android 8.0.0;it-IT;releaseEnv release)",
        "Content-Type": "application/json; charset=UTF-8",
        "Accept-Encoding": "gzip",
        "X-Roo-Country": "uk",
    }

    ab_tests_url = "https://api.deliveroo.com/orderapp/v1/config?ab_tests=fex_259%2Cnux_soft_login_android%2Cfex_223" \
                   "%2Cprom_1819_xp_showing_discounted_price_for_items_over_mov%2Ccl_2679" \
                   "%2Ccht_391_home_remove_fulfillment_methods%2Cnux-personalisation%2Cfex_284%2Cpmts" \
                   "-286_privacy_consent_experiment%2Ccl_2681%2Ccl_2678%2Ccl_2680%2Ccht_758_increase_content_density" \
                   "%2Cfex_228&features=tier_switching_clients_enabled%2Cconeng_19%2Cplus_category_discount" \
                   "%2Cuse_credits_offers_endpoint%2Crate_dine_in_orders_enabled%2Cen_572_clients_enabled" \
                   "%2Cdeep_link_home_filter%2Cmenu_supports_toggle_dropdown_action%2Cfavourites_entrypoint_enabled" \
                   "%2Cnew_menu_enabled%2Ccpr_798_great_value%2Cuse_restaurant_info_blocks%2Cdeloveroo_logo_enabled" \
                   "%2Corder_details_substitutions_and_unavailable_items%2Ccollect_245_clients%2Cclients-home-feed" \
                   "-modals-enabled%2Candroid_cadev_125%2Candroid_order_status_automatic_update_on_push_notification" \
                   "%2Corder_status_new_rewards_banner%2Cage_verification_dob%2Cmp_24" \
                   "%2Candroid_display_order_status_route%2Cmerch_330_banner_card%2Cinlife_mobile_verification" \
                   "%2Candroid_show_knet%2Cuse_graphql_mock_endpoint%2Candroid_ui_background" \
                   "%2Candroid_capability_home_feed_card_tall%2Cfc_117_android%2Crisk_264_android" \
                   "%2Candroid_promotion_tag%2Candroid_circular_carousels%2Candroid_require_drinking_age_verification" \
                   "%2Cdp_229_android%2Csave_payment_card_opt_in_out_feature_enabled%2Corder_status_ux_feedback" \
                   "%2Chome_344_android%2Candroid_limit_query_results%2Cmenu_supports_menu_item_carousel_cards" \
                   "%2Cdrn_support%2Cpeg_1295_android%2Cmobile_datadog_sdk%2Cmenu_footer_animations_enabled" \
                   "%2Coauth_flow_mobile%2Cplus_account_banner%2Cco_menus_reviews_entrypoint_enabled" \
                   "%2Cin_app_post_order_tipping%2Cnew_menu_opt_in%2Ctc_91_header%2Cmenu_swipe_between_categories" \
                   "%2Ccc_1835_android%2Cplus_experience%2Candroid_save_basket_to_disk%2Cshow_scheduled_ranges" \
                   "%2Cmenu_supports_option_navigation_group%2Cmenu_supports_list_row_block" \
                   "%2Cbasket_replace_old_item_substitution_with_new%2Cproject_rainfall_enabled_clients" \
                   "%2Cmenu_supports_tab_bar_on_category_screen%2Cflash_deals_menu_basket_mobile" \
                   "%2Cco_android_country_min_version_enabled%2Chome_175_android%2Chome_486_android%2Cloy_477" \
                   "%2Cmenu_supports_carousel_cards%2Cdp_350_android%2Cdeloveroo_app_icon_enabled" \
                   "%2Cdisplay_dob_in_user_profile%2Cmenu_use_product_meta_instead_of_nutritional_info" \
                   "%2Cmenu_supports_carousel_layouts%2Cmenu_supports_configurable_grid%2Cclient_consumer_mfa_login" \
                   "%2Cmenu_progress_bar%2Cplus_cta_new_menu%2Cmerchandising_card_capability%2Ctds_service_redemption" \
                   "%2Candroid_track_order_status_route%2Cemployee_android_checkout%2Cbas_171_android" \
                   "%2Cmenu_modifier_future_amount_mov%2Candroid_offers_visibility_information_progress_bar" \
                   "%2Candroid_new_offer_progress_bar%2Cdp_346_change_app_icon" \
                   "%2Corder_status_rider_route_from_endpoint%2Candroid_cadev_73%2Cnux_show_progress_bar" \
                   "%2Ccht_175_improved_scroll_tracking_on_home%2Ccollect_386_android%2Crisk_132_android_3" \
                   "%2Candroid_disable_fetch_orders%2Cnew_menu_search_enabled%2Cmenu_supports_reorder_target" \
                   "%2Candroid_capability_home_feed_span_countdown%2Cmenu_supports_tall_menu_item_card" \
                   "%2Calipayplus_alipay_hk_enabled%2Cpeg_1193_android%2Cmy_orders_ugc_entrypoint" \
                   "%2Candroid_order_status_christmas_delight%2Chome_326_android%2Cpup_18_clients" \
                   "%2Chack_19_in_app_updates_employees%2Cis_employee%2Cproject_rainfall_client_webview_enabled" \
                   "%2Creorder_widget%2Corder_status_substitutions_and_unavailable_items" \
                   "%2Cmenu_supports_tall_cards_in_carousels%2Corder_history_post_order_tipping" \
                   "%2Cconsumer_charitable_donations%2Cfb_sdk_init_enabled%2Ccollect_385_android" \
                   "%2Cmenu_scroll_tracking%2Cugc_track_tag_properties%2Cvalue_based_bidding" \
                   "%2Candroid_basket_plus_popup%2Cexpand_android_order_tracker_banner%2Cdine_in_clients" \
                   "%2Ccutlery_selection_required "

    @commands.Cog.listener()
    async def on_message(self, ctx: discord.Message):
        """Message listener for order verification"""
        if ctx.author.id == self.bot.user.id:
            return

        if isinstance(ctx.channel, discord.DMChannel):
            # Verification should only happen in DMs
            try:
                user = self.session.query(DeliverooUser).filter_by(discord_id=str(ctx.author.id)).first()
            except Exception as e:
                await ctx.reply(content=e.with_traceback(e.__traceback__).__str__())
                return

            if ctx.content == "I agree to this charge. I acknowledge that once this goes through, there is no " \
                              f"cancelling the order. Auth Key: {user.auth_token}":
                # Now we can go ahead with placing the order.
                r = requests.session()
                headers = self.base_headers
                headers.update(
                    {
                        "X-Roo-Guid": user.roo_uid,
                        "X-Roo-Sticky-Guid": user.roo_uid,
                        "Authorization": OTP.decrypt_auth(user.auth_token),
                        "X-APOLLO-OPERATION-NAME": "ExecutePaymentPlan",
                        "X-APOLLO-CACHE-FETCH-STRATEGY": "NETWORK_ONLY",
                        "X-APOLLO-EXPIRE-TIMEOUT": "0",
                        "X-APOLLO-EXPIRE-AFTER-READ": "false",
                        "X-APOLLO-PREFETCH": "false",
                        "X-APOLLO-CACHE-DO-NOT-STORE": "false",
                    }
                )

                query = {
                    "operationName": "ExecutePaymentPlan",
                    "query": "mutation ExecutePaymentPlan($payment_plan_id: ID!, $payment_option_data: InputPaymentOptionData, $challenge_result: ChallengeResult, $table_number: String, $marketing_preference_results: MarketingPreferenceResults, $payPalDeviceData: String, $params: [InputParam!]) { result: execute_payment_plan(payment_plan_id: $payment_plan_id, payment_option_data: $payment_option_data, challenge_result: $challenge_result, capabilities: {challenge_capabilities: [OVER_18_AGE_CONFIRMATION], wallets: []}, table_number: $table_number, marketing_preferences: $marketing_preference_results, device_data: $payPalDeviceData, params: $params) { __typename order_id challenge { __typename ... on AppChallenge { title decoded_payload { __typename ... on WechatPayAppChallengeDecodedPayload { prepay_id partner_id sign timestamp nonce pkg } } } ... on BrowserChallenge { url } ... on WebChallenge { url title method } ... on ExpiryDateChallenge { title message input_error_message } ... on Over18AgeConfirmationChallenge { title message ok_cta cancel_cta } ... on PaypalReAuthChallenge { event_tracking { __typename event_name } message cancel_cta } } } }",
                    "variables": {
                        "payment_plan_id": user.payment_id,
                        "payment_option_data": None,
                        "challenge_result": None,
                        "marketing_preference_results": {"results": []},
                        "payPalDeviceData": None,
                        "params": [],
                    },
                }

                response = r.post(
                    f"https://api.deliveroo.com/checkout-api/graphql-query",
                    verify=True,
                    headers=headers,
                    data=json.dumps(query),
                )

                if response.status_code == 200:
                    await ctx.reply("Order has been placed, enjoy!")
                else:
                    await ctx.reply("Order failed. Please report to Sketch#4374.")

    @app_commands.command(name="login", description="Attempt to login to Deliveroo")
    @app_commands.guilds(Object(id=997708022778450020))
    async def login(self, interaction: Interaction):
        await interaction.response.defer()
        # First lets determine if the user exists
        try:
            user = self.session.query(DeliverooUser).filter_by(discord_id=str(interaction.user.id)).first()
        except Exception as e:
            await interaction.followup.send(e.with_traceback(e.__traceback__))
            return

        headers = self.base_headers
        roo_uid = str(uuid.uuid4())
        headers.update(
            {
                "X-Roo-Guid": roo_uid,
                "X-Roo-Sticky-Guid": roo_uid
            }
        )

        idfv = id_generator(16, "1234567890abcdef")
        idfa = str(uuid.uuid4())

        dev_prop = {
            "App Namespace": "com.deliveroo.orderapp",
            "App Version": "3.109.0",
            "Platform": "Android",
            "OS Version": "8.0.0",
            "Device Model": "samsung SM-G935F",
            "Device Type": "Phone",
            "Locale": "en_UK",
            "IDFV": idfv,
            "IDFA": idfa,
            "Google Pay Status": "unknown",
            "Device Locale": "en_UK",
            "Device Language": "en-UK",
            "mvt_mfa_high_risk_login_android": "feature"
        }

        dev_data = base64.b64encode(bytes(json.dumps(dev_prop), "utf-8")).decode()

        r = requests.session()
        r.cookies.set("roo_guid", roo_uid, domain="api.deliveroo.com", path="/")
        r.cookies.set("roo_super_properties", dev_data, domain="api.deliveroo.com", path="/")

        response = r.get(self.ab_tests_url, verify=True, headers=headers)

        # registering device info
        response = r.post("https://api.deliveroo.com/orderapp/v1/session", verify=True, headers=headers,
                          data=json.dumps({"first_install": True}))

        print(response.text)
        print(response.status_code)
        if response.status_code != 201:
            await interaction.followup.send(content="Failed to initiate session.")
            return

        response = r.post("https://api.deliveroo.com/orderapp/v1/check-email", verify=True, headers=headers,
                          data=json.dumps({"email_address": user.email}))
        x = json.loads(response.text)

        if not x["registered"]:
            await interaction.followup.send(content="Email does not exist.")
            return

        basic_auth = base64.b64encode(bytes(f"{user.email}:{user.password}", "utf-8")).decode()
        headers.update({
            "Authorization": f"Basic {basic_auth}",
            "X-Roo-Challenge-Support": "passcode"
        })

        response = r.post("https://api.deliveroo.com/orderapp/v1/login?track=1", verify=True, headers=headers,
                          data=json.dumps({"client_type": "orderapp_android"}))

        print(response.status_code)
        print(response.text)
        if response.status_code != 423:
            await interaction.followup.send(content="Failed to login.")
            return

        x = json.loads(response.text)
        if x["message"] == "mfa_required":
            # 2fa triggered
            data = {
                "challenge": "sms:passcode",
                "mfa_token": x["mfa_token"],
                "trigger": "send",
            }

            response = r.post(
                "https://api.deliveroo.com/orderapp/v1/login/initiate_challenge",
                verify=True,
                headers=headers,
                data=json.dumps(data),
            )

            if response.status_code != 200:
                await interaction.followup.send(content="Failed to send OTP code.")
                return

        self.cache.update({interaction.user.id: self.Cache(basic_auth, x["mfa_token"], r.cookies, roo_uid)})
        await interaction.followup.send(content="Login succeeded. You should receive a text message from Deliveroo. "
                                                "Run /deliveroo otp and enter that code.")

    @app_commands.command(name="otp", description="Validate Deliveroo OTP")
    @app_commands.guilds(Object(id=997708022778450020))
    async def otp(self, interaction: Interaction):
        cache = self.cache[interaction.user.id]
        await interaction.response.send_modal(OTP(cache.auth, cache.mfa, cache.cookies, cache.uid, self.session))


class OTP(discord.ui.Modal, title="Deliveroo OTP"):
    def __init__(self, auth: str, mfa: str, cookies, uid, session):
        super().__init__()
        self.auth = auth
        self.mfa = mfa
        self.cookies = cookies
        self.uid = uid
        self.session = session

    name = discord.ui.TextInput(
        label="Enter your OTP",
        placeholder="000000",
    )

    KEY = b""
    IV = b""

    @staticmethod
    def decrypt_auth(key: str) -> str:
        byte_val = bytes.fromhex(key)
        cipher = AES.new(OTP.KEY, AES.MODE_CBC, iv=OTP.IV)
        result = cipher.decrypt(byte_val)
        return result.decode("utf-8")


    @staticmethod
    def encode_hex_to_str(array: bytes) -> str:
        hextable = "0123456789abcdef"
        ret = ""
        for b in array:
            ret += hextable[b >> 4]
            ret += hextable[b & 0x0f]

        return ret

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = requests.session()
        r.cookies = self.cookies

        headers = Deliveroo.base_headers
        headers.update(
            {
                "X-Roo-Guid": self.uid,
                "X-Roo-Sticky-Guid": self.uid,
                "Authorization": f"Basic {self.auth}",
            }
        )

        print(self.auth)
        print(self.mfa)
        print(self.name.value)
        print(type(self.name.value))

        data = {
            "challenge": "sms:passcode",
            "client_type": "orderapp_android",
            "data": {"passcode": str(self.name.value)},
            "mfa_token": self.mfa,
        }

        response = r.post(
            "https://api.deliveroo.com/orderapp/v1/login/complete_challenge",
            verify=True,
            headers=headers,
            data=json.dumps(data),
        )

        print(response.text)
        print(response.status_code)
        if response.status_code != 200:
            await interaction.followup.send(content="Failed to verify OTP", ephemeral=True)
            return

        x = json.loads(response.text)
        userid = str(x["id"])
        sestk = x["session_token"]
        auth_str = f"{userid}:orderapp_android,{sestk}"
        auth64 = base64.b64encode(bytes(auth_str, "utf-8")).decode()
        auth = f"Basic {auth64}"

        try:
            cipher = AES.new(self.KEY, AES.MODE_CBC, iv=self.IV)
            encrypted_auth = cipher.encrypt(pad(bytes(auth, "utf-8"), AES.block_size))
            user = self.session.query(DeliverooUser).filter_by(discord_id=str(interaction.user.id)).first()
            user.auth_token = OTP.encode_hex_to_str(encrypted_auth)
            user.roo_uid = self.uid
            self.session.commit()
        except Exception as e:
            await interaction.followup.send(e.with_traceback(e.__traceback__))
            return

        await interaction.followup.send(content="OTP verified, you can now use Demae Deliveroo!", ephemeral=True)


async def setup(bot):
    await bot.add_cog(Deliveroo(bot), guilds=[Object(id=997708022778450020)])
