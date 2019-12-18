/******/ (function (modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if (installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
            /******/
        }
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
            /******/
        };
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
        /******/
    }
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function (exports, name, getter) {
/******/ 		if (!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
            /******/
        }
        /******/
    };
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function (exports) {
/******/ 		if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
            /******/
        }
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
        /******/
    };
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function (value, mode) {
/******/ 		if (mode & 1) value = __webpack_require__(value);
/******/ 		if (mode & 8) return value;
/******/ 		if ((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if (mode & 2 && typeof value != 'string') for (var key in value) __webpack_require__.d(ns, key, function (key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
        /******/
    };
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function (module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
        /******/
    };
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function (object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./Assets/js/chatbot/src/chatbot.ts");
    /******/
})
/************************************************************************/
/******/({

/***/ "./Assets/js/chatbot/src/chatbot.ts":
/*!******************************************!*\
  !*** ./Assets/js/chatbot/src/chatbot.ts ***!
  \******************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

            "use strict";

            Object.defineProperty(exports, "__esModule", { value: true });
            var jss_1 = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");
            var jss_preset_default_1 = __webpack_require__(/*! jss-preset-default */ "./node_modules/jss-preset-default/dist/jss-preset-default.esm.js");
            var Vue = __webpack_require__(/*! vue */ "./node_modules/vue/dist/vue.min.js");
            var BotUI = __webpack_require__(/*! botui/build/botui */ "./node_modules/botui/build/botui.js");
            var signalR = __webpack_require__(/*! @microsoft/signalr */ "./node_modules/@microsoft/signalr/dist/esm/index.js");
            var ChatBot = /** @class */ (function () {
                function ChatBot(iconBackgroundColor, textColor, chatBackgroundColor) {
                    if (iconBackgroundColor === void 0) { iconBackgroundColor = "#0689ec"; }
                    if (textColor === void 0) { textColor = "#fff"; }
                    if (chatBackgroundColor === void 0) { chatBackgroundColor = "#fff"; }
                    jss_1.default.setup(jss_preset_default_1.default());
                    this.iconBackgroundColor = iconBackgroundColor;
                    this.textColor = textColor;
                    this.chatBackgroundColor = chatBackgroundColor;
                    this.initialize();
                }
                ChatBot.prototype.initialize = function () {
                    this.createElement();
                    this.bindEvents();
                    this.initializeBotUI();
                    this.initializeSignalR();
                };
                ChatBot.prototype.styles = function () {
                    return {
                        chat__container: {
                            color: this.textColor,
                            position: 'fixed',
                            bottom: '16px',
                            right: '16px',
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'flex-end'
                        },
                        chat__screen: {
                            color: this.textColor,
                            width: '300px',
                            height: '450px',
                            backgroundColor: this.chatBackgroundColor,
                            marginBottom: '8px',
                            borderRadius: '8px',
                            padding: '8px',
                            boxShadow: "rgba(0, 0, 0, 0.16) 0px 5px 40px",
                            transition: "all 0.5s ease-out"
                        },
                        chat__icon: {
                            color: this.textColor,
                            width: '70px',
                            padding: '16px',
                            cursor: 'pointer',
                            backgroundColor: this.iconBackgroundColor,
                            borderRadius: '100px',
                            boxShadow: "rgba(0, 0, 0, 0.16) 0px 5px 40px",
                            transition: "all 0.5s ease-out"
                        },
                        chat__icon_images: {
                            fill: this.textColor
                        }
                    };
                };
                ChatBot.prototype.createElement = function () {
                    var classes = jss_1.default.createStyleSheet(this.styles()).attach().classes;
                    document.body.innerHTML += "\n            <div id=\"chat-container\" class=\"" + classes.chat__container + "\">\n                    <div id=\"chat-panel\" style=\"display: none;\" class=\"" + classes.chat__screen + "\">\n                        <div id=\"my-botui-app\">\n                            <bot-ui></bot-ui>\n                        </div>\n                    </div>\n                    <div id=\"chatbot-controls\" class=\"" + classes.chat__icon + "\">\n                        <span id=\"open-chat\">\n                            <svg class=\"" + classes.chat__icon_images + "\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" x=\"0px\" y=\"0px\" viewBox=\"0 0 1000 1000\" enable-background=\"new 0 0 1000 1000\" xml:space=\"preserve\">\n                            <g><g transform=\"translate(0.000000,512.000000) scale(0.100000,-0.100000)\"><path d=\"M795,4984.8c-323.3-86.1-575.9-344.4-662-671.5c-44-164.5-44-6237.1,0-6401.6c86.1-331,340.5-587.4,669.6-673.5c91.8-23,243-28.7,778.7-28.7h665.8V-3661c0-954.7,0-952.8,112.9-1048.4c70.8-57.4,162.6-80.4,264-61.2c63.1,11.5,191.3,130.1,1058,996.8l985.3,983.4H6879c2429.8,0,2315-5.7,2544.6,116.7c133.9,72.7,300.4,241.1,369.3,376.9c112.9,221.9,107.1,40.2,107.1,3409.4c0,2714.8-3.8,3105.1-28.7,3204.6c-86.1,329.1-342.5,583.5-673.4,669.6C9035.2,5028.8,953.8,5026.9,795,4984.8z M9146.2,4353.4c28.7-21,70.8-63.1,91.8-91.8l40.2-51.7V1112.4V-1985l-40.2-51.7c-21.1-28.7-63.2-70.8-91.8-91.8c-51.6-40.2-63.1-40.2-2389.6-45.9l-2337.9-3.8L3638-2958.9l-778.7-778.7v778.7v778.7l-973.8,5.7c-950.9,5.7-975.7,7.7-1027.4,45.9c-28.7,21-70.8,63.1-91.8,91.8c-40.2,51.7-40.2,55.5-45.9,3097.5c-1.9,1676,0,3072.6,5.7,3107.1c13.4,76.5,93.7,174.1,172.2,208.5c47.8,21,772.9,24.9,4126.8,21l4069.4-3.8L9146.2,4353.4z\" /><path d=\"M3041.1,3151.9c-78.4-34.4-158.8-132-172.2-208.5c-5.7-34.4-9.6-294.6-5.7-581.6c5.7-489.8,7.7-522.3,45.9-572.1c97.6-130.1,101.4-132,562.5-132s464.9,1.9,562.5,132c38.3,49.7,40.2,76.5,40.2,623.7c0,547.2-1.9,574-40.2,623.7c-95.7,128.2-105.2,132-539.5,135.8C3194.2,3176.8,3085.1,3173,3041.1,3151.9z\" /><path d=\"M6102.2,3151.9c-78.4-34.4-158.8-132-172.2-208.5c-5.7-34.4-9.6-294.6-5.7-581.6c5.7-489.8,7.6-522.3,45.9-572.1c97.6-130.1,101.4-132,562.5-132s464.9,1.9,562.5,132c38.3,49.7,40.2,76.5,40.2,623.7c0,547.2-1.9,574-40.2,623.7c-95.7,128.2-105.2,132-539.5,135.8C6255.3,3176.8,6146.2,3173,6102.2,3151.9z\" /><path d=\"M2907.2-83.3c-47.8-45.9-47.8-49.7-47.8-411.3c0-361.6,0-365.4,47.8-411.3l45.9-47.8h2049.1h2049.1l45.9,47.8c47.8,45.9,47.8,49.7,47.8,411.3c0,361.6,0,365.4-47.8,411.3l-45.9,47.8H5002.1H2953.1L2907.2-83.3z\" /></g></g>\n                            </svg>\n                        </span>\n                        <span id=\"close-chat\" style=\"display: none; padding: 4px;\">\n                            <svg class=\"" + classes.chat__icon_images + "\" version=\"1.1\" id=\"Capa_1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" x=\"0px\" y=\"0px\"\n\t                                viewBox=\"0 0 47.971 47.971\" style=\"enable-background:new 0 0 47.971 47.971;\" xml:space=\"preserve\">\n                                    <g>\n\t                                <path d=\"M28.228,23.986L47.092,5.122c1.172-1.171,1.172-3.071,0-4.242c-1.172-1.172-3.07-1.172-4.242,0L23.986,19.744L5.121,0.88\n\t\t                                c-1.172-1.172-3.07-1.172-4.242,0c-1.172,1.171-1.172,3.071,0,4.242l18.865,18.864L0.879,42.85c-1.172,1.171-1.172,3.071,0,4.242\n\t\t                                C1.465,47.677,2.233,47.97,3,47.97s1.535-0.293,2.121-0.879l18.865-18.864L42.85,47.091c0.586,0.586,1.354,0.879,2.121,0.879\n\t\t                                s1.535-0.293,2.121-0.879c1.172-1.171,1.172-3.071,0-4.242L28.228,23.986z\"/></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g><g></g>\n                            </svg>\n                        </span>\n                    </div>\n            </div>";
                };
                ChatBot.prototype.bindEvents = function () {
                    var _this = this;
                    var chatContainer = document.querySelector("#chat-container");
                    var chatbotControls = document.querySelector("#chatbot-controls");
                    var chatPanel = document.querySelector("#chat-panel");
                    var closeIcon = document.querySelector("#close-chat");
                    var openIcon = document.querySelector("#open-chat");
                    chatContainer.onclick = function () {
                        if (_this.isInitialized)
                            return;
                        _this.initializeSignalR();
                        //this.initializeBotUI();
                        _this.isInitialized = true;
                    };
                    chatbotControls.onclick = function () {
                        chatPanel.style.display = chatPanel.style.display == "block" ? "none" : "block";
                        closeIcon.style.display = chatPanel.style.display == "block" ? "block" : "none";
                        openIcon.style.display = chatPanel.style.display == "block" ? "none" : "block";
                    };
                };
                ChatBot.prototype.initializeSignalR = function () {
                    var _this = this;
                    var key = "X-API-KEY";
                    this.signalRConnection = new signalR.HubConnectionBuilder()
                        .withUrl("https://localhost:44323/chathub?" + key + "=[APIKEY]")
                        .configureLogging(signalR.LogLevel.Information)
                        .withAutomaticReconnect()
                        .build();
                    this.signalRConnection.start().catch(function (err) {
                        _this.removeChat();
                        return console.error(err.toString());
                    });
                    this.signalRConnection.on("ReceiveMessage", function (message) {
                        console.log(message);
                        _this.botUI.message.bot({
                            type: 'text',
                            content: message
                        });
                    });
                };
                ChatBot.prototype.initializeBotUI = function () {
                    var _this = this;
                    this.botUI = new BotUI('my-botui-app', {
                        vue: Vue
                    });
                    this.botUI.message.bot({
                        type: 'text',
                        content: 'Hi, how can I help you?'
                    }).then(function () {
                        _this.botUI.action.text({
                            type: 'text',
                            action: {
                                value: '',
                                placeholder: 'Enter your command here'
                            }
                        }).then(function (res) {
                            _this.sendMessage(res);
                        });
                    });
                };
                ChatBot.prototype.sendMessage = function (message) {
                    this.signalRConnection.invoke("SendMessageToCaller", message.value)
                        .catch(function (err) {
                            return console.error(err.toString());
                        });
                };
                // Returns true if chat existed and element is removed
                ChatBot.prototype.removeChat = function () {
                    var chatContainer = document.querySelector("#chat-container");
                    if (chatContainer) {
                        chatContainer.remove();
                        return true;
                    }
                    return false;
                };
                return ChatBot;
            }());
            exports.ChatBot = ChatBot;
            exports.default = ChatBot;
            new ChatBot();


            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/arrayWithoutHoles.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/arrayWithoutHoles.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _arrayWithoutHoles; });
            function _arrayWithoutHoles(arr) {
                if (Array.isArray(arr)) {
                    for (var i = 0, arr2 = new Array(arr.length); i < arr.length; i++) {
                        arr2[i] = arr[i];
                    }

                    return arr2;
                }
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/assertThisInitialized.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/assertThisInitialized.js ***!
  \**************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _assertThisInitialized; });
            function _assertThisInitialized(self) {
                if (self === void 0) {
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                }

                return self;
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/createClass.js":
/*!****************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/createClass.js ***!
  \****************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _createClass; });
            function _defineProperties(target, props) {
                for (var i = 0; i < props.length; i++) {
                    var descriptor = props[i];
                    descriptor.enumerable = descriptor.enumerable || false;
                    descriptor.configurable = true;
                    if ("value" in descriptor) descriptor.writable = true;
                    Object.defineProperty(target, descriptor.key, descriptor);
                }
            }

            function _createClass(Constructor, protoProps, staticProps) {
                if (protoProps) _defineProperties(Constructor.prototype, protoProps);
                if (staticProps) _defineProperties(Constructor, staticProps);
                return Constructor;
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/extends.js":
/*!************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/extends.js ***!
  \************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _extends; });
            function _extends() {
                _extends = Object.assign || function (target) {
                    for (var i = 1; i < arguments.length; i++) {
                        var source = arguments[i];

                        for (var key in source) {
                            if (Object.prototype.hasOwnProperty.call(source, key)) {
                                target[key] = source[key];
                            }
                        }
                    }

                    return target;
                };

                return _extends.apply(this, arguments);
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/inheritsLoose.js":
/*!******************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/inheritsLoose.js ***!
  \******************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _inheritsLoose; });
            function _inheritsLoose(subClass, superClass) {
                subClass.prototype = Object.create(superClass.prototype);
                subClass.prototype.constructor = subClass;
                subClass.__proto__ = superClass;
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/iterableToArray.js":
/*!********************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/iterableToArray.js ***!
  \********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _iterableToArray; });
            function _iterableToArray(iter) {
                if (Symbol.iterator in Object(iter) || Object.prototype.toString.call(iter) === "[object Arguments]") return Array.from(iter);
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/nonIterableSpread.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/nonIterableSpread.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _nonIterableSpread; });
            function _nonIterableSpread() {
                throw new TypeError("Invalid attempt to spread non-iterable instance");
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/objectWithoutPropertiesLoose.js":
/*!*********************************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/objectWithoutPropertiesLoose.js ***!
  \*********************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _objectWithoutPropertiesLoose; });
            function _objectWithoutPropertiesLoose(source, excluded) {
                if (source == null) return {};
                var target = {};
                var sourceKeys = Object.keys(source);
                var key, i;

                for (i = 0; i < sourceKeys.length; i++) {
                    key = sourceKeys[i];
                    if (excluded.indexOf(key) >= 0) continue;
                    target[key] = source[key];
                }

                return target;
            }

            /***/
        }),

/***/ "./node_modules/@babel/runtime/helpers/esm/toConsumableArray.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/toConsumableArray.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return _toConsumableArray; });
/* harmony import */ var _arrayWithoutHoles__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./arrayWithoutHoles */ "./node_modules/@babel/runtime/helpers/esm/arrayWithoutHoles.js");
/* harmony import */ var _iterableToArray__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./iterableToArray */ "./node_modules/@babel/runtime/helpers/esm/iterableToArray.js");
/* harmony import */ var _nonIterableSpread__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./nonIterableSpread */ "./node_modules/@babel/runtime/helpers/esm/nonIterableSpread.js");



            function _toConsumableArray(arr) {
                return Object(_arrayWithoutHoles__WEBPACK_IMPORTED_MODULE_0__["default"])(arr) || Object(_iterableToArray__WEBPACK_IMPORTED_MODULE_1__["default"])(arr) || Object(_nonIterableSpread__WEBPACK_IMPORTED_MODULE_2__["default"])();
            }

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/AbortController.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/AbortController.js ***!
  \*********************************************************************/
/*! exports provided: AbortController */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AbortController", function () { return AbortController; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // Rough polyfill of https://developer.mozilla.org/en-US/docs/Web/API/AbortController
            // We don't actually ever use the API being polyfilled, we always use the polyfill because
            // it's a very new API right now.
            // Not exported from index.
            /** @private */
            var AbortController = /** @class */ (function () {
                function AbortController() {
                    this.isAborted = false;
                    this.onabort = null;
                }
                AbortController.prototype.abort = function () {
                    if (!this.isAborted) {
                        this.isAborted = true;
                        if (this.onabort) {
                            this.onabort();
                        }
                    }
                };
                Object.defineProperty(AbortController.prototype, "signal", {
                    get: function () {
                        return this;
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(AbortController.prototype, "aborted", {
                    get: function () {
                        return this.isAborted;
                    },
                    enumerable: true,
                    configurable: true
                });
                return AbortController;
            }());

            //# sourceMappingURL=AbortController.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/DefaultHttpClient.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/DefaultHttpClient.js ***!
  \***********************************************************************/
/*! exports provided: DefaultHttpClient */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "DefaultHttpClient", function () { return DefaultHttpClient; });
/* harmony import */ var _Errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Errors */ "./node_modules/@microsoft/signalr/dist/esm/Errors.js");
/* harmony import */ var _HttpClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./HttpClient */ "./node_modules/@microsoft/signalr/dist/esm/HttpClient.js");
/* harmony import */ var _NodeHttpClient__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./NodeHttpClient */ "./node_modules/@microsoft/signalr/dist/esm/NodeHttpClient.js");
/* harmony import */ var _XhrHttpClient__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./XhrHttpClient */ "./node_modules/@microsoft/signalr/dist/esm/XhrHttpClient.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __extends = (undefined && undefined.__extends) || (function () {
                var extendStatics = Object.setPrototypeOf ||
                    ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
                    function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
                return function (d, b) {
                    extendStatics(d, b);
                    function __() { this.constructor = d; }
                    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
                };
            })();




            /** Default implementation of {@link @microsoft/signalr.HttpClient}. */
            var DefaultHttpClient = /** @class */ (function (_super) {
                __extends(DefaultHttpClient, _super);
                /** Creates a new instance of the {@link @microsoft/signalr.DefaultHttpClient}, using the provided {@link @microsoft/signalr.ILogger} to log messages. */
                function DefaultHttpClient(logger) {
                    var _this = _super.call(this) || this;
                    if (typeof XMLHttpRequest !== "undefined") {
                        _this.httpClient = new _XhrHttpClient__WEBPACK_IMPORTED_MODULE_3__["XhrHttpClient"](logger);
                    }
                    else {
                        _this.httpClient = new _NodeHttpClient__WEBPACK_IMPORTED_MODULE_2__["NodeHttpClient"](logger);
                    }
                    return _this;
                }
                /** @inheritDoc */
                DefaultHttpClient.prototype.send = function (request) {
                    // Check that abort was not signaled before calling send
                    if (request.abortSignal && request.abortSignal.aborted) {
                        return Promise.reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["AbortError"]());
                    }
                    if (!request.method) {
                        return Promise.reject(new Error("No method defined."));
                    }
                    if (!request.url) {
                        return Promise.reject(new Error("No url defined."));
                    }
                    return this.httpClient.send(request);
                };
                DefaultHttpClient.prototype.getCookieString = function (url) {
                    return this.httpClient.getCookieString(url);
                };
                return DefaultHttpClient;
            }(_HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpClient"]));

            //# sourceMappingURL=DefaultHttpClient.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/DefaultReconnectPolicy.js":
/*!****************************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/DefaultReconnectPolicy.js ***!
  \****************************************************************************/
/*! exports provided: DefaultReconnectPolicy */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "DefaultReconnectPolicy", function () { return DefaultReconnectPolicy; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // 0, 2, 10, 30 second delays before reconnect attempts.
            var DEFAULT_RETRY_DELAYS_IN_MILLISECONDS = [0, 2000, 10000, 30000, null];
            /** @private */
            var DefaultReconnectPolicy = /** @class */ (function () {
                function DefaultReconnectPolicy(retryDelays) {
                    this.retryDelays = retryDelays !== undefined ? retryDelays.concat([null]) : DEFAULT_RETRY_DELAYS_IN_MILLISECONDS;
                }
                DefaultReconnectPolicy.prototype.nextRetryDelayInMilliseconds = function (retryContext) {
                    return this.retryDelays[retryContext.previousRetryCount];
                };
                return DefaultReconnectPolicy;
            }());

            //# sourceMappingURL=DefaultReconnectPolicy.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/Errors.js":
/*!************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/Errors.js ***!
  \************************************************************/
/*! exports provided: HttpError, TimeoutError, AbortError */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HttpError", function () { return HttpError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "TimeoutError", function () { return TimeoutError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AbortError", function () { return AbortError; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __extends = (undefined && undefined.__extends) || (function () {
                var extendStatics = Object.setPrototypeOf ||
                    ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
                    function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
                return function (d, b) {
                    extendStatics(d, b);
                    function __() { this.constructor = d; }
                    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
                };
            })();
            /** Error thrown when an HTTP request fails. */
            var HttpError = /** @class */ (function (_super) {
                __extends(HttpError, _super);
                /** Constructs a new instance of {@link @microsoft/signalr.HttpError}.
                 *
                 * @param {string} errorMessage A descriptive error message.
                 * @param {number} statusCode The HTTP status code represented by this error.
                 */
                function HttpError(errorMessage, statusCode) {
                    var _newTarget = this.constructor;
                    var _this = this;
                    var trueProto = _newTarget.prototype;
                    _this = _super.call(this, errorMessage) || this;
                    _this.statusCode = statusCode;
                    // Workaround issue in Typescript compiler
                    // https://github.com/Microsoft/TypeScript/issues/13965#issuecomment-278570200
                    _this.__proto__ = trueProto;
                    return _this;
                }
                return HttpError;
            }(Error));

            /** Error thrown when a timeout elapses. */
            var TimeoutError = /** @class */ (function (_super) {
                __extends(TimeoutError, _super);
                /** Constructs a new instance of {@link @microsoft/signalr.TimeoutError}.
                 *
                 * @param {string} errorMessage A descriptive error message.
                 */
                function TimeoutError(errorMessage) {
                    var _newTarget = this.constructor;
                    if (errorMessage === void 0) { errorMessage = "A timeout occurred."; }
                    var _this = this;
                    var trueProto = _newTarget.prototype;
                    _this = _super.call(this, errorMessage) || this;
                    // Workaround issue in Typescript compiler
                    // https://github.com/Microsoft/TypeScript/issues/13965#issuecomment-278570200
                    _this.__proto__ = trueProto;
                    return _this;
                }
                return TimeoutError;
            }(Error));

            /** Error thrown when an action is aborted. */
            var AbortError = /** @class */ (function (_super) {
                __extends(AbortError, _super);
                /** Constructs a new instance of {@link AbortError}.
                 *
                 * @param {string} errorMessage A descriptive error message.
                 */
                function AbortError(errorMessage) {
                    var _newTarget = this.constructor;
                    if (errorMessage === void 0) { errorMessage = "An abort occurred."; }
                    var _this = this;
                    var trueProto = _newTarget.prototype;
                    _this = _super.call(this, errorMessage) || this;
                    // Workaround issue in Typescript compiler
                    // https://github.com/Microsoft/TypeScript/issues/13965#issuecomment-278570200
                    _this.__proto__ = trueProto;
                    return _this;
                }
                return AbortError;
            }(Error));

            //# sourceMappingURL=Errors.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/HandshakeProtocol.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/HandshakeProtocol.js ***!
  \***********************************************************************/
/*! exports provided: HandshakeProtocol */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* WEBPACK VAR INJECTION */(function (Buffer) {/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HandshakeProtocol", function () { return HandshakeProtocol; });
/* harmony import */ var _TextMessageFormat__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./TextMessageFormat */ "./node_modules/@microsoft/signalr/dist/esm/TextMessageFormat.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
                // Copyright (c) .NET Foundation. All rights reserved.
                // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.


                /** @private */
                var HandshakeProtocol = /** @class */ (function () {
                    function HandshakeProtocol() {
                    }
                    // Handshake request is always JSON
                    HandshakeProtocol.prototype.writeHandshakeRequest = function (handshakeRequest) {
                        return _TextMessageFormat__WEBPACK_IMPORTED_MODULE_0__["TextMessageFormat"].write(JSON.stringify(handshakeRequest));
                    };
                    HandshakeProtocol.prototype.parseHandshakeResponse = function (data) {
                        var responseMessage;
                        var messageData;
                        var remainingData;
                        if (Object(_Utils__WEBPACK_IMPORTED_MODULE_1__["isArrayBuffer"])(data) || (typeof Buffer !== "undefined" && data instanceof Buffer)) {
                            // Format is binary but still need to read JSON text from handshake response
                            var binaryData = new Uint8Array(data);
                            var separatorIndex = binaryData.indexOf(_TextMessageFormat__WEBPACK_IMPORTED_MODULE_0__["TextMessageFormat"].RecordSeparatorCode);
                            if (separatorIndex === -1) {
                                throw new Error("Message is incomplete.");
                            }
                            // content before separator is handshake response
                            // optional content after is additional messages
                            var responseLength = separatorIndex + 1;
                            messageData = String.fromCharCode.apply(null, binaryData.slice(0, responseLength));
                            remainingData = (binaryData.byteLength > responseLength) ? binaryData.slice(responseLength).buffer : null;
                        }
                        else {
                            var textData = data;
                            var separatorIndex = textData.indexOf(_TextMessageFormat__WEBPACK_IMPORTED_MODULE_0__["TextMessageFormat"].RecordSeparator);
                            if (separatorIndex === -1) {
                                throw new Error("Message is incomplete.");
                            }
                            // content before separator is handshake response
                            // optional content after is additional messages
                            var responseLength = separatorIndex + 1;
                            messageData = textData.substring(0, responseLength);
                            remainingData = (textData.length > responseLength) ? textData.substring(responseLength) : null;
                        }
                        // At this point we should have just the single handshake message
                        var messages = _TextMessageFormat__WEBPACK_IMPORTED_MODULE_0__["TextMessageFormat"].parse(messageData);
                        var response = JSON.parse(messages[0]);
                        if (response.type) {
                            throw new Error("Expected a handshake response from the server.");
                        }
                        responseMessage = response;
                        // multiple messages could have arrived with handshake
                        // return additional data to be parsed as usual, or null if all parsed
                        return [remainingData, responseMessage];
                    };
                    return HandshakeProtocol;
                }());

                //# sourceMappingURL=HandshakeProtocol.js.map
                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../../../../buffer/index.js */ "./node_modules/buffer/index.js").Buffer))

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/HttpClient.js":
/*!****************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/HttpClient.js ***!
  \****************************************************************/
/*! exports provided: HttpResponse, HttpClient */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HttpResponse", function () { return HttpResponse; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HttpClient", function () { return HttpClient; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __assign = (undefined && undefined.__assign) || Object.assign || function (t) {
                for (var s, i = 1, n = arguments.length; i < n; i++) {
                    s = arguments[i];
                    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                        t[p] = s[p];
                }
                return t;
            };
            /** Represents an HTTP response. */
            var HttpResponse = /** @class */ (function () {
                function HttpResponse(statusCode, statusText, content) {
                    this.statusCode = statusCode;
                    this.statusText = statusText;
                    this.content = content;
                }
                return HttpResponse;
            }());

            /** Abstraction over an HTTP client.
             *
             * This class provides an abstraction over an HTTP client so that a different implementation can be provided on different platforms.
             */
            var HttpClient = /** @class */ (function () {
                function HttpClient() {
                }
                HttpClient.prototype.get = function (url, options) {
                    return this.send(__assign({}, options, { method: "GET", url: url }));
                };
                HttpClient.prototype.post = function (url, options) {
                    return this.send(__assign({}, options, { method: "POST", url: url }));
                };
                HttpClient.prototype.delete = function (url, options) {
                    return this.send(__assign({}, options, { method: "DELETE", url: url }));
                };
                /** Gets all cookies that apply to the specified URL.
                 *
                 * @param url The URL that the cookies are valid for.
                 * @returns {string} A string containing all the key-value cookie pairs for the specified URL.
                 */
                // @ts-ignore
                HttpClient.prototype.getCookieString = function (url) {
                    return "";
                };
                return HttpClient;
            }());

            //# sourceMappingURL=HttpClient.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/HttpConnection.js":
/*!********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/HttpConnection.js ***!
  \********************************************************************/
/*! exports provided: HttpConnection, TransportSendQueue */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HttpConnection", function () { return HttpConnection; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "TransportSendQueue", function () { return TransportSendQueue; });
/* harmony import */ var _DefaultHttpClient__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./DefaultHttpClient */ "./node_modules/@microsoft/signalr/dist/esm/DefaultHttpClient.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony import */ var _LongPollingTransport__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./LongPollingTransport */ "./node_modules/@microsoft/signalr/dist/esm/LongPollingTransport.js");
/* harmony import */ var _ServerSentEventsTransport__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./ServerSentEventsTransport */ "./node_modules/@microsoft/signalr/dist/esm/ServerSentEventsTransport.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
/* harmony import */ var _WebSocketTransport__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./WebSocketTransport */ "./node_modules/@microsoft/signalr/dist/esm/WebSocketTransport.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };







            var MAX_REDIRECTS = 100;
            var WebSocketModule = null;
            var EventSourceModule = null;
            if (_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isNode && "function" !== "undefined") {
                // In order to ignore the dynamic require in webpack builds we need to do this magic
                // @ts-ignore: TS doesn't know about these names
                var requireFunc = true ? require : undefined;
                WebSocketModule = requireFunc("ws");
                EventSourceModule = requireFunc("eventsource");
            }
            /** @private */
            var HttpConnection = /** @class */ (function () {
                function HttpConnection(url, options) {
                    if (options === void 0) { options = {}; }
                    this.features = {};
                    this.negotiateVersion = 1;
                    _Utils__WEBPACK_IMPORTED_MODULE_5__["Arg"].isRequired(url, "url");
                    this.logger = Object(_Utils__WEBPACK_IMPORTED_MODULE_5__["createLogger"])(options.logger);
                    this.baseUrl = this.resolveUrl(url);
                    options = options || {};
                    options.logMessageContent = options.logMessageContent || false;
                    if (!_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isNode && typeof WebSocket !== "undefined" && !options.WebSocket) {
                        options.WebSocket = WebSocket;
                    }
                    else if (_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isNode && !options.WebSocket) {
                        if (WebSocketModule) {
                            options.WebSocket = WebSocketModule;
                        }
                    }
                    if (!_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isNode && typeof EventSource !== "undefined" && !options.EventSource) {
                        options.EventSource = EventSource;
                    }
                    else if (_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isNode && !options.EventSource) {
                        if (typeof EventSourceModule !== "undefined") {
                            options.EventSource = EventSourceModule;
                        }
                    }
                    this.httpClient = options.httpClient || new _DefaultHttpClient__WEBPACK_IMPORTED_MODULE_0__["DefaultHttpClient"](this.logger);
                    this.connectionState = "Disconnected" /* Disconnected */;
                    this.connectionStarted = false;
                    this.options = options;
                    this.onreceive = null;
                    this.onclose = null;
                }
                HttpConnection.prototype.start = function (transferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var message, message;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    transferFormat = transferFormat || _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"].Binary;
                                    _Utils__WEBPACK_IMPORTED_MODULE_5__["Arg"].isIn(transferFormat, _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"], "transferFormat");
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Starting connection with transfer format '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"][transferFormat] + "'.");
                                    if (this.connectionState !== "Disconnected" /* Disconnected */) {
                                        return [2 /*return*/, Promise.reject(new Error("Cannot start an HttpConnection that is not in the 'Disconnected' state."))];
                                    }
                                    this.connectionState = "Connecting " /* Connecting */;
                                    this.startInternalPromise = this.startInternal(transferFormat);
                                    return [4 /*yield*/, this.startInternalPromise];
                                case 1:
                                    _a.sent();
                                    if (!(this.connectionState === "Disconnecting" /* Disconnecting */)) return [3 /*break*/, 3];
                                    message = "Failed to start the HttpConnection before stop() was called.";
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, message);
                                    // We cannot await stopPromise inside startInternal since stopInternal awaits the startInternalPromise.
                                    return [4 /*yield*/, this.stopPromise];
                                case 2:
                                    // We cannot await stopPromise inside startInternal since stopInternal awaits the startInternalPromise.
                                    _a.sent();
                                    return [2 /*return*/, Promise.reject(new Error(message))];
                                case 3:
                                    if (this.connectionState !== "Connected" /* Connected */) {
                                        message = "HttpConnection.startInternal completed gracefully but didn't enter the connection into the connected state!";
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, message);
                                        return [2 /*return*/, Promise.reject(new Error(message))];
                                    }
                                    _a.label = 4;
                                case 4:
                                    this.connectionStarted = true;
                                    return [2 /*return*/];
                            }
                        });
                    });
                };
                HttpConnection.prototype.send = function (data) {
                    if (this.connectionState !== "Connected" /* Connected */) {
                        return Promise.reject(new Error("Cannot send data if the connection is not in the 'Connected' State."));
                    }
                    if (!this.sendQueue) {
                        this.sendQueue = new TransportSendQueue(this.transport);
                    }
                    // Transport will not be null if state is connected
                    return this.sendQueue.send(data);
                };
                HttpConnection.prototype.stop = function (error) {
                    return __awaiter(this, void 0, void 0, function () {
                        var _this = this;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    if (this.connectionState === "Disconnected" /* Disconnected */) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Call to HttpConnection.stop(" + error + ") ignored because the connection is already in the disconnected state.");
                                        return [2 /*return*/, Promise.resolve()];
                                    }
                                    if (this.connectionState === "Disconnecting" /* Disconnecting */) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Call to HttpConnection.stop(" + error + ") ignored because the connection is already in the disconnecting state.");
                                        return [2 /*return*/, this.stopPromise];
                                    }
                                    this.connectionState = "Disconnecting" /* Disconnecting */;
                                    this.stopPromise = new Promise(function (resolve) {
                                        // Don't complete stop() until stopConnection() completes.
                                        _this.stopPromiseResolver = resolve;
                                    });
                                    // stopInternal should never throw so just observe it.
                                    return [4 /*yield*/, this.stopInternal(error)];
                                case 1:
                                    // stopInternal should never throw so just observe it.
                                    _a.sent();
                                    return [4 /*yield*/, this.stopPromise];
                                case 2:
                                    _a.sent();
                                    return [2 /*return*/];
                            }
                        });
                    });
                };
                HttpConnection.prototype.stopInternal = function (error) {
                    return __awaiter(this, void 0, void 0, function () {
                        var e_1, e_2, e_3;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    // Set error as soon as possible otherwise there is a race between
                                    // the transport closing and providing an error and the error from a close message
                                    // We would prefer the close message error.
                                    this.stopError = error;
                                    _a.label = 1;
                                case 1:
                                    _a.trys.push([1, 3, , 4]);
                                    return [4 /*yield*/, this.startInternalPromise];
                                case 2:
                                    _a.sent();
                                    return [3 /*break*/, 4];
                                case 3:
                                    e_1 = _a.sent();
                                    return [3 /*break*/, 4];
                                case 4:
                                    if (!this.sendQueue) return [3 /*break*/, 9];
                                    _a.label = 5;
                                case 5:
                                    _a.trys.push([5, 7, , 8]);
                                    return [4 /*yield*/, this.sendQueue.stop()];
                                case 6:
                                    _a.sent();
                                    return [3 /*break*/, 8];
                                case 7:
                                    e_2 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "TransportSendQueue.stop() threw error '" + e_2 + "'.");
                                    return [3 /*break*/, 8];
                                case 8:
                                    this.sendQueue = undefined;
                                    _a.label = 9;
                                case 9:
                                    if (!this.transport) return [3 /*break*/, 14];
                                    _a.label = 10;
                                case 10:
                                    _a.trys.push([10, 12, , 13]);
                                    return [4 /*yield*/, this.transport.stop()];
                                case 11:
                                    _a.sent();
                                    return [3 /*break*/, 13];
                                case 12:
                                    e_3 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "HttpConnection.transport.stop() threw error '" + e_3 + "'.");
                                    this.stopConnection();
                                    return [3 /*break*/, 13];
                                case 13:
                                    this.transport = undefined;
                                    return [3 /*break*/, 15];
                                case 14:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "HttpConnection.transport is undefined in HttpConnection.stop() because start() failed.");
                                    this.stopConnection();
                                    _a.label = 15;
                                case 15: return [2 /*return*/];
                            }
                        });
                    });
                };
                HttpConnection.prototype.startInternal = function (transferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var url, negotiateResponse, redirects, _loop_1, this_1, e_4;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    url = this.baseUrl;
                                    this.accessTokenFactory = this.options.accessTokenFactory;
                                    _a.label = 1;
                                case 1:
                                    _a.trys.push([1, 12, , 13]);
                                    if (!this.options.skipNegotiation) return [3 /*break*/, 5];
                                    if (!(this.options.transport === _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].WebSockets)) return [3 /*break*/, 3];
                                    // No need to add a connection ID in this case
                                    this.transport = this.constructTransport(_ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].WebSockets);
                                    // We should just call connect directly in this case.
                                    // No fallback or negotiate in this case.
                                    return [4 /*yield*/, this.startTransport(url, transferFormat)];
                                case 2:
                                    // We should just call connect directly in this case.
                                    // No fallback or negotiate in this case.
                                    _a.sent();
                                    return [3 /*break*/, 4];
                                case 3: throw new Error("Negotiation can only be skipped when using the WebSocket transport directly.");
                                case 4: return [3 /*break*/, 11];
                                case 5:
                                    negotiateResponse = null;
                                    redirects = 0;
                                    _loop_1 = function () {
                                        var accessToken_1;
                                        return __generator(this, function (_a) {
                                            switch (_a.label) {
                                                case 0: return [4 /*yield*/, this_1.getNegotiationResponse(url)];
                                                case 1:
                                                    negotiateResponse = _a.sent();
                                                    // the user tries to stop the connection when it is being started
                                                    if (this_1.connectionState === "Disconnecting" /* Disconnecting */ || this_1.connectionState === "Disconnected" /* Disconnected */) {
                                                        throw new Error("The connection was stopped during negotiation.");
                                                    }
                                                    if (negotiateResponse.error) {
                                                        throw new Error(negotiateResponse.error);
                                                    }
                                                    if (negotiateResponse.ProtocolVersion) {
                                                        throw new Error("Detected a connection attempt to an ASP.NET SignalR Server. This client only supports connecting to an ASP.NET Core SignalR Server. See https://aka.ms/signalr-core-differences for details.");
                                                    }
                                                    if (negotiateResponse.url) {
                                                        url = negotiateResponse.url;
                                                    }
                                                    if (negotiateResponse.accessToken) {
                                                        accessToken_1 = negotiateResponse.accessToken;
                                                        this_1.accessTokenFactory = function () { return accessToken_1; };
                                                    }
                                                    redirects++;
                                                    return [2 /*return*/];
                                            }
                                        });
                                    };
                                    this_1 = this;
                                    _a.label = 6;
                                case 6: return [5 /*yield**/, _loop_1()];
                                case 7:
                                    _a.sent();
                                    _a.label = 8;
                                case 8:
                                    if (negotiateResponse.url && redirects < MAX_REDIRECTS) return [3 /*break*/, 6];
                                    _a.label = 9;
                                case 9:
                                    if (redirects === MAX_REDIRECTS && negotiateResponse.url) {
                                        throw new Error("Negotiate redirection limit exceeded.");
                                    }
                                    return [4 /*yield*/, this.createTransport(url, this.options.transport, negotiateResponse, transferFormat)];
                                case 10:
                                    _a.sent();
                                    _a.label = 11;
                                case 11:
                                    if (this.transport instanceof _LongPollingTransport__WEBPACK_IMPORTED_MODULE_3__["LongPollingTransport"]) {
                                        this.features.inherentKeepAlive = true;
                                    }
                                    if (this.connectionState === "Connecting " /* Connecting */) {
                                        // Ensure the connection transitions to the connected state prior to completing this.startInternalPromise.
                                        // start() will handle the case when stop was called and startInternal exits still in the disconnecting state.
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "The HttpConnection connected successfully.");
                                        this.connectionState = "Connected" /* Connected */;
                                    }
                                    return [3 /*break*/, 13];
                                case 12:
                                    e_4 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "Failed to start the connection: " + e_4);
                                    this.connectionState = "Disconnected" /* Disconnected */;
                                    this.transport = undefined;
                                    return [2 /*return*/, Promise.reject(e_4)];
                                case 13: return [2 /*return*/];
                            }
                        });
                    });
                };
                HttpConnection.prototype.getNegotiationResponse = function (url) {
                    return __awaiter(this, void 0, void 0, function () {
                        var _a, headers, token, negotiateUrl, response, negotiateResponse, e_5;
                        return __generator(this, function (_b) {
                            switch (_b.label) {
                                case 0:
                                    if (!this.accessTokenFactory) return [3 /*break*/, 2];
                                    return [4 /*yield*/, this.accessTokenFactory()];
                                case 1:
                                    token = _b.sent();
                                    if (token) {
                                        headers = (_a = {},
                                            _a["Authorization"] = "Bearer " + token,
                                            _a);
                                    }
                                    _b.label = 2;
                                case 2:
                                    negotiateUrl = this.resolveNegotiateUrl(url);
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Sending negotiation request: " + negotiateUrl + ".");
                                    _b.label = 3;
                                case 3:
                                    _b.trys.push([3, 5, , 6]);
                                    return [4 /*yield*/, this.httpClient.post(negotiateUrl, {
                                        content: "",
                                        headers: headers,
                                    })];
                                case 4:
                                    response = _b.sent();
                                    if (response.statusCode !== 200) {
                                        return [2 /*return*/, Promise.reject(new Error("Unexpected status code returned from negotiate " + response.statusCode))];
                                    }
                                    negotiateResponse = JSON.parse(response.content);
                                    if (!negotiateResponse.negotiateVersion || negotiateResponse.negotiateVersion < 1) {
                                        // Negotiate version 0 doesn't use connectionToken
                                        // So we set it equal to connectionId so all our logic can use connectionToken without being aware of the negotiate version
                                        negotiateResponse.connectionToken = negotiateResponse.connectionId;
                                    }
                                    return [2 /*return*/, negotiateResponse];
                                case 5:
                                    e_5 = _b.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "Failed to complete negotiation with the server: " + e_5);
                                    return [2 /*return*/, Promise.reject(e_5)];
                                case 6: return [2 /*return*/];
                            }
                        });
                    });
                };
                HttpConnection.prototype.createConnectUrl = function (url, connectionToken) {
                    if (!connectionToken) {
                        return url;
                    }
                    return url + (url.indexOf("?") === -1 ? "?" : "&") + ("id=" + connectionToken);
                };
                HttpConnection.prototype.createTransport = function (url, requestedTransport, negotiateResponse, requestedTransferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var connectUrl, transportExceptions, transports, negotiate, _i, transports_1, endpoint, transportOrError, ex_1, ex_2, message;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    connectUrl = this.createConnectUrl(url, negotiateResponse.connectionToken);
                                    if (!this.isITransport(requestedTransport)) return [3 /*break*/, 2];
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Connection was provided an instance of ITransport, using that directly.");
                                    this.transport = requestedTransport;
                                    return [4 /*yield*/, this.startTransport(connectUrl, requestedTransferFormat)];
                                case 1:
                                    _a.sent();
                                    this.connectionId = negotiateResponse.connectionId;
                                    return [2 /*return*/];
                                case 2:
                                    transportExceptions = [];
                                    transports = negotiateResponse.availableTransports || [];
                                    negotiate = negotiateResponse;
                                    _i = 0, transports_1 = transports;
                                    _a.label = 3;
                                case 3:
                                    if (!(_i < transports_1.length)) return [3 /*break*/, 13];
                                    endpoint = transports_1[_i];
                                    transportOrError = this.resolveTransportOrError(endpoint, requestedTransport, requestedTransferFormat);
                                    if (!(transportOrError instanceof Error)) return [3 /*break*/, 4];
                                    // Store the error and continue, we don't want to cause a re-negotiate in these cases
                                    transportExceptions.push(endpoint.transport + " failed: " + transportOrError);
                                    return [3 /*break*/, 12];
                                case 4:
                                    if (!this.isITransport(transportOrError)) return [3 /*break*/, 12];
                                    this.transport = transportOrError;
                                    if (!!negotiate) return [3 /*break*/, 9];
                                    _a.label = 5;
                                case 5:
                                    _a.trys.push([5, 7, , 8]);
                                    return [4 /*yield*/, this.getNegotiationResponse(url)];
                                case 6:
                                    negotiate = _a.sent();
                                    return [3 /*break*/, 8];
                                case 7:
                                    ex_1 = _a.sent();
                                    return [2 /*return*/, Promise.reject(ex_1)];
                                case 8:
                                    connectUrl = this.createConnectUrl(url, negotiate.connectionToken);
                                    _a.label = 9;
                                case 9:
                                    _a.trys.push([9, 11, , 12]);
                                    return [4 /*yield*/, this.startTransport(connectUrl, requestedTransferFormat)];
                                case 10:
                                    _a.sent();
                                    this.connectionId = negotiate.connectionId;
                                    return [2 /*return*/];
                                case 11:
                                    ex_2 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "Failed to start the transport '" + endpoint.transport + "': " + ex_2);
                                    negotiate = undefined;
                                    transportExceptions.push(endpoint.transport + " failed: " + ex_2);
                                    if (this.connectionState !== "Connecting " /* Connecting */) {
                                        message = "Failed to select transport before stop() was called.";
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, message);
                                        return [2 /*return*/, Promise.reject(new Error(message))];
                                    }
                                    return [3 /*break*/, 12];
                                case 12:
                                    _i++;
                                    return [3 /*break*/, 3];
                                case 13:
                                    if (transportExceptions.length > 0) {
                                        return [2 /*return*/, Promise.reject(new Error("Unable to connect to the server with any of the available transports. " + transportExceptions.join(" ")))];
                                    }
                                    return [2 /*return*/, Promise.reject(new Error("None of the transports supported by the client are supported by the server."))];
                            }
                        });
                    });
                };
                HttpConnection.prototype.constructTransport = function (transport) {
                    switch (transport) {
                        case _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].WebSockets:
                            if (!this.options.WebSocket) {
                                throw new Error("'WebSocket' is not supported in your environment.");
                            }
                            return new _WebSocketTransport__WEBPACK_IMPORTED_MODULE_6__["WebSocketTransport"](this.httpClient, this.accessTokenFactory, this.logger, this.options.logMessageContent || false, this.options.WebSocket);
                        case _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].ServerSentEvents:
                            if (!this.options.EventSource) {
                                throw new Error("'EventSource' is not supported in your environment.");
                            }
                            return new _ServerSentEventsTransport__WEBPACK_IMPORTED_MODULE_4__["ServerSentEventsTransport"](this.httpClient, this.accessTokenFactory, this.logger, this.options.logMessageContent || false, this.options.EventSource);
                        case _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].LongPolling:
                            return new _LongPollingTransport__WEBPACK_IMPORTED_MODULE_3__["LongPollingTransport"](this.httpClient, this.accessTokenFactory, this.logger, this.options.logMessageContent || false);
                        default:
                            throw new Error("Unknown transport: " + transport + ".");
                    }
                };
                HttpConnection.prototype.startTransport = function (url, transferFormat) {
                    var _this = this;
                    this.transport.onreceive = this.onreceive;
                    this.transport.onclose = function (e) { return _this.stopConnection(e); };
                    return this.transport.connect(url, transferFormat);
                };
                HttpConnection.prototype.resolveTransportOrError = function (endpoint, requestedTransport, requestedTransferFormat) {
                    var transport = _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][endpoint.transport];
                    if (transport === null || transport === undefined) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Skipping transport '" + endpoint.transport + "' because it is not supported by this client.");
                        return new Error("Skipping transport '" + endpoint.transport + "' because it is not supported by this client.");
                    }
                    else {
                        if (transportMatches(requestedTransport, transport)) {
                            var transferFormats = endpoint.transferFormats.map(function (s) { return _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"][s]; });
                            if (transferFormats.indexOf(requestedTransferFormat) >= 0) {
                                if ((transport === _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].WebSockets && !this.options.WebSocket) ||
                                    (transport === _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"].ServerSentEvents && !this.options.EventSource)) {
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Skipping transport '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' because it is not supported in your environment.'");
                                    return new Error("'" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' is not supported in your environment.");
                                }
                                else {
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Selecting transport '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "'.");
                                    try {
                                        return this.constructTransport(transport);
                                    }
                                    catch (ex) {
                                        return ex;
                                    }
                                }
                            }
                            else {
                                this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Skipping transport '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' because it does not support the requested transfer format '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"][requestedTransferFormat] + "'.");
                                return new Error("'" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' does not support " + _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"][requestedTransferFormat] + ".");
                            }
                        }
                        else {
                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Skipping transport '" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' because it was disabled by the client.");
                            return new Error("'" + _ITransport__WEBPACK_IMPORTED_MODULE_2__["HttpTransportType"][transport] + "' is disabled by the client.");
                        }
                    }
                };
                HttpConnection.prototype.isITransport = function (transport) {
                    return transport && typeof (transport) === "object" && "connect" in transport;
                };
                HttpConnection.prototype.stopConnection = function (error) {
                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "HttpConnection.stopConnection(" + error + ") called while in state " + this.connectionState + ".");
                    this.transport = undefined;
                    // If we have a stopError, it takes precedence over the error from the transport
                    error = this.stopError || error;
                    this.stopError = undefined;
                    if (this.connectionState === "Disconnected" /* Disconnected */) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Debug, "Call to HttpConnection.stopConnection(" + error + ") was ignored because the connection is already in the disconnected state.");
                        return;
                    }
                    if (this.connectionState === "Connecting " /* Connecting */) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Warning, "Call to HttpConnection.stopConnection(" + error + ") was ignored because the connection hasn't yet left the in the connecting state.");
                        return;
                    }
                    if (this.connectionState === "Disconnecting" /* Disconnecting */) {
                        // A call to stop() induced this call to stopConnection and needs to be completed.
                        // Any stop() awaiters will be scheduled to continue after the onclose callback fires.
                        this.stopPromiseResolver();
                    }
                    if (error) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "Connection disconnected with error '" + error + "'.");
                    }
                    else {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Information, "Connection disconnected.");
                    }
                    this.connectionId = undefined;
                    this.connectionState = "Disconnected" /* Disconnected */;
                    if (this.onclose && this.connectionStarted) {
                        this.connectionStarted = false;
                        try {
                            this.onclose(error);
                        }
                        catch (e) {
                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Error, "HttpConnection.onclose(" + error + ") threw error '" + e + "'.");
                        }
                    }
                };
                HttpConnection.prototype.resolveUrl = function (url) {
                    // startsWith is not supported in IE
                    if (url.lastIndexOf("https://", 0) === 0 || url.lastIndexOf("http://", 0) === 0) {
                        return url;
                    }
                    if (!_Utils__WEBPACK_IMPORTED_MODULE_5__["Platform"].isBrowser || !window.document) {
                        throw new Error("Cannot resolve '" + url + "'.");
                    }
                    // Setting the url to the href propery of an anchor tag handles normalization
                    // for us. There are 3 main cases.
                    // 1. Relative path normalization e.g "b" -> "http://localhost:5000/a/b"
                    // 2. Absolute path normalization e.g "/a/b" -> "http://localhost:5000/a/b"
                    // 3. Networkpath reference normalization e.g "//localhost:5000/a/b" -> "http://localhost:5000/a/b"
                    var aTag = window.document.createElement("a");
                    aTag.href = url;
                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Information, "Normalizing '" + url + "' to '" + aTag.href + "'.");
                    return aTag.href;
                };
                HttpConnection.prototype.resolveNegotiateUrl = function (url) {
                    var index = url.indexOf("?");
                    var negotiateUrl = url.substring(0, index === -1 ? url.length : index);
                    if (negotiateUrl[negotiateUrl.length - 1] !== "/") {
                        negotiateUrl += "/";
                    }
                    negotiateUrl += "negotiate";
                    negotiateUrl += index === -1 ? "" : url.substring(index);
                    if (negotiateUrl.indexOf("negotiateVersion") === -1) {
                        negotiateUrl += index === -1 ? "?" : "&";
                        negotiateUrl += "negotiateVersion=" + this.negotiateVersion;
                    }
                    return negotiateUrl;
                };
                return HttpConnection;
            }());

            function transportMatches(requestedTransport, actualTransport) {
                return !requestedTransport || ((actualTransport & requestedTransport) !== 0);
            }
            /** @private */
            var TransportSendQueue = /** @class */ (function () {
                function TransportSendQueue(transport) {
                    this.transport = transport;
                    this.buffer = [];
                    this.executing = true;
                    this.sendBufferedData = new PromiseSource();
                    this.transportResult = new PromiseSource();
                    this.sendLoopPromise = this.sendLoop();
                }
                TransportSendQueue.prototype.send = function (data) {
                    this.bufferData(data);
                    if (!this.transportResult) {
                        this.transportResult = new PromiseSource();
                    }
                    return this.transportResult.promise;
                };
                TransportSendQueue.prototype.stop = function () {
                    this.executing = false;
                    this.sendBufferedData.resolve();
                    return this.sendLoopPromise;
                };
                TransportSendQueue.prototype.bufferData = function (data) {
                    if (this.buffer.length && typeof (this.buffer[0]) !== typeof (data)) {
                        throw new Error("Expected data to be of type " + typeof (this.buffer) + " but was of type " + typeof (data));
                    }
                    this.buffer.push(data);
                    this.sendBufferedData.resolve();
                };
                TransportSendQueue.prototype.sendLoop = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        var transportResult, data, error_1;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    if (false) { }
                                    return [4 /*yield*/, this.sendBufferedData.promise];
                                case 1:
                                    _a.sent();
                                    if (!this.executing) {
                                        if (this.transportResult) {
                                            this.transportResult.reject("Connection stopped.");
                                        }
                                        return [3 /*break*/, 6];
                                    }
                                    this.sendBufferedData = new PromiseSource();
                                    transportResult = this.transportResult;
                                    this.transportResult = undefined;
                                    data = typeof (this.buffer[0]) === "string" ?
                                        this.buffer.join("") :
                                        TransportSendQueue.concatBuffers(this.buffer);
                                    this.buffer.length = 0;
                                    _a.label = 2;
                                case 2:
                                    _a.trys.push([2, 4, , 5]);
                                    return [4 /*yield*/, this.transport.send(data)];
                                case 3:
                                    _a.sent();
                                    transportResult.resolve();
                                    return [3 /*break*/, 5];
                                case 4:
                                    error_1 = _a.sent();
                                    transportResult.reject(error_1);
                                    return [3 /*break*/, 5];
                                case 5: return [3 /*break*/, 0];
                                case 6: return [2 /*return*/];
                            }
                        });
                    });
                };
                TransportSendQueue.concatBuffers = function (arrayBuffers) {
                    var totalLength = arrayBuffers.map(function (b) { return b.byteLength; }).reduce(function (a, b) { return a + b; });
                    var result = new Uint8Array(totalLength);
                    var offset = 0;
                    for (var _i = 0, arrayBuffers_1 = arrayBuffers; _i < arrayBuffers_1.length; _i++) {
                        var item = arrayBuffers_1[_i];
                        result.set(new Uint8Array(item), offset);
                        offset += item.byteLength;
                    }
                    return result;
                };
                return TransportSendQueue;
            }());

            var PromiseSource = /** @class */ (function () {
                function PromiseSource() {
                    var _this = this;
                    this.promise = new Promise(function (resolve, reject) {
                        var _a;
                        return _a = [resolve, reject], _this.resolver = _a[0], _this.rejecter = _a[1], _a;
                    });
                }
                PromiseSource.prototype.resolve = function () {
                    this.resolver();
                };
                PromiseSource.prototype.reject = function (reason) {
                    this.rejecter(reason);
                };
                return PromiseSource;
            }());
            //# sourceMappingURL=HttpConnection.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/HubConnection.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/HubConnection.js ***!
  \*******************************************************************/
/*! exports provided: HubConnectionState, HubConnection */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HubConnectionState", function () { return HubConnectionState; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HubConnection", function () { return HubConnection; });
/* harmony import */ var _HandshakeProtocol__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./HandshakeProtocol */ "./node_modules/@microsoft/signalr/dist/esm/HandshakeProtocol.js");
/* harmony import */ var _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./IHubProtocol */ "./node_modules/@microsoft/signalr/dist/esm/IHubProtocol.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _Subject__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Subject */ "./node_modules/@microsoft/signalr/dist/esm/Subject.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };





            var DEFAULT_TIMEOUT_IN_MS = 30 * 1000;
            var DEFAULT_PING_INTERVAL_IN_MS = 15 * 1000;
            /** Describes the current state of the {@link HubConnection} to the server. */
            var HubConnectionState;
            (function (HubConnectionState) {
                /** The hub connection is disconnected. */
                HubConnectionState["Disconnected"] = "Disconnected";
                /** The hub connection is connecting. */
                HubConnectionState["Connecting"] = "Connecting";
                /** The hub connection is connected. */
                HubConnectionState["Connected"] = "Connected";
                /** The hub connection is disconnecting. */
                HubConnectionState["Disconnecting"] = "Disconnecting";
                /** The hub connection is reconnecting. */
                HubConnectionState["Reconnecting"] = "Reconnecting";
            })(HubConnectionState || (HubConnectionState = {}));
            /** Represents a connection to a SignalR Hub. */
            var HubConnection = /** @class */ (function () {
                function HubConnection(connection, logger, protocol, reconnectPolicy) {
                    var _this = this;
                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isRequired(connection, "connection");
                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isRequired(logger, "logger");
                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isRequired(protocol, "protocol");
                    this.serverTimeoutInMilliseconds = DEFAULT_TIMEOUT_IN_MS;
                    this.keepAliveIntervalInMilliseconds = DEFAULT_PING_INTERVAL_IN_MS;
                    this.logger = logger;
                    this.protocol = protocol;
                    this.connection = connection;
                    this.reconnectPolicy = reconnectPolicy;
                    this.handshakeProtocol = new _HandshakeProtocol__WEBPACK_IMPORTED_MODULE_0__["HandshakeProtocol"]();
                    this.connection.onreceive = function (data) { return _this.processIncomingData(data); };
                    this.connection.onclose = function (error) { return _this.connectionClosed(error); };
                    this.callbacks = {};
                    this.methods = {};
                    this.closedCallbacks = [];
                    this.reconnectingCallbacks = [];
                    this.reconnectedCallbacks = [];
                    this.invocationId = 0;
                    this.receivedHandshakeResponse = false;
                    this.connectionState = HubConnectionState.Disconnected;
                    this.connectionStarted = false;
                    this.cachedPingMessage = this.protocol.writeMessage({ type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Ping });
                }
                /** @internal */
                // Using a public static factory method means we can have a private constructor and an _internal_
                // create method that can be used by HubConnectionBuilder. An "internal" constructor would just
                // be stripped away and the '.d.ts' file would have no constructor, which is interpreted as a
                // public parameter-less constructor.
                HubConnection.create = function (connection, logger, protocol, reconnectPolicy) {
                    return new HubConnection(connection, logger, protocol, reconnectPolicy);
                };
                Object.defineProperty(HubConnection.prototype, "state", {
                    /** Indicates the state of the {@link HubConnection} to the server. */
                    get: function () {
                        return this.connectionState;
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(HubConnection.prototype, "connectionId", {
                    /** Represents the connection id of the {@link HubConnection} on the server. The connection id will be null when the connection is either
                     *  in the disconnected state or if the negotiation step was skipped.
                     */
                    get: function () {
                        return this.connection ? (this.connection.connectionId || null) : null;
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(HubConnection.prototype, "baseUrl", {
                    /** Indicates the url of the {@link HubConnection} to the server. */
                    get: function () {
                        return this.connection.baseUrl || "";
                    },
                    /**
                     * Sets a new url for the HubConnection. Note that the url can only be changed when the connection is in either the Disconnected or
                     * Reconnecting states.
                     * @param {string} url The url to connect to.
                     */
                    set: function (url) {
                        if (this.connectionState !== HubConnectionState.Disconnected && this.connectionState !== HubConnectionState.Reconnecting) {
                            throw new Error("The HubConnection must be in the Disconnected or Reconnecting state to change the url.");
                        }
                        if (!url) {
                            throw new Error("The HubConnection url must be a valid url.");
                        }
                        this.connection.baseUrl = url;
                    },
                    enumerable: true,
                    configurable: true
                });
                /** Starts the connection.
                 *
                 * @returns {Promise<void>} A Promise that resolves when the connection has been successfully established, or rejects with an error.
                 */
                HubConnection.prototype.start = function () {
                    this.startPromise = this.startWithStateTransitions();
                    return this.startPromise;
                };
                HubConnection.prototype.startWithStateTransitions = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        var e_1;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    if (this.connectionState !== HubConnectionState.Disconnected) {
                                        return [2 /*return*/, Promise.reject(new Error("Cannot start a HubConnection that is not in the 'Disconnected' state."))];
                                    }
                                    this.connectionState = HubConnectionState.Connecting;
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Starting HubConnection.");
                                    _a.label = 1;
                                case 1:
                                    _a.trys.push([1, 3, , 4]);
                                    return [4 /*yield*/, this.startInternal()];
                                case 2:
                                    _a.sent();
                                    this.connectionState = HubConnectionState.Connected;
                                    this.connectionStarted = true;
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "HubConnection connected successfully.");
                                    return [3 /*break*/, 4];
                                case 3:
                                    e_1 = _a.sent();
                                    this.connectionState = HubConnectionState.Disconnected;
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "HubConnection failed to start successfully because of error '" + e_1 + "'.");
                                    return [2 /*return*/, Promise.reject(e_1)];
                                case 4: return [2 /*return*/];
                            }
                        });
                    });
                };
                HubConnection.prototype.startInternal = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        var handshakePromise, handshakeRequest, e_2;
                        var _this = this;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    this.stopDuringStartError = undefined;
                                    this.receivedHandshakeResponse = false;
                                    handshakePromise = new Promise(function (resolve, reject) {
                                        _this.handshakeResolver = resolve;
                                        _this.handshakeRejecter = reject;
                                    });
                                    return [4 /*yield*/, this.connection.start(this.protocol.transferFormat)];
                                case 1:
                                    _a.sent();
                                    _a.label = 2;
                                case 2:
                                    _a.trys.push([2, 5, , 7]);
                                    handshakeRequest = {
                                        protocol: this.protocol.name,
                                        version: this.protocol.version,
                                    };
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Sending handshake request.");
                                    return [4 /*yield*/, this.sendMessage(this.handshakeProtocol.writeHandshakeRequest(handshakeRequest))];
                                case 3:
                                    _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Using HubProtocol '" + this.protocol.name + "'.");
                                    // defensively cleanup timeout in case we receive a message from the server before we finish start
                                    this.cleanupTimeout();
                                    this.resetTimeoutPeriod();
                                    this.resetKeepAliveInterval();
                                    return [4 /*yield*/, handshakePromise];
                                case 4:
                                    _a.sent();
                                    // It's important to check the stopDuringStartError instead of just relying on the handshakePromise
                                    // being rejected on close, because this continuation can run after both the handshake completed successfully
                                    // and the connection was closed.
                                    if (this.stopDuringStartError) {
                                        // It's important to throw instead of returning a rejected promise, because we don't want to allow any state
                                        // transitions to occur between now and the calling code observing the exceptions. Returning a rejected promise
                                        // will cause the calling continuation to get scheduled to run later.
                                        throw this.stopDuringStartError;
                                    }
                                    return [3 /*break*/, 7];
                                case 5:
                                    e_2 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Hub handshake failed with error '" + e_2 + "' during start(). Stopping HubConnection.");
                                    this.cleanupTimeout();
                                    this.cleanupPingTimer();
                                    // HttpConnection.stop() should not complete until after the onclose callback is invoked.
                                    // This will transition the HubConnection to the disconnected state before HttpConnection.stop() completes.
                                    return [4 /*yield*/, this.connection.stop(e_2)];
                                case 6:
                                    // HttpConnection.stop() should not complete until after the onclose callback is invoked.
                                    // This will transition the HubConnection to the disconnected state before HttpConnection.stop() completes.
                                    _a.sent();
                                    throw e_2;
                                case 7: return [2 /*return*/];
                            }
                        });
                    });
                };
                /** Stops the connection.
                 *
                 * @returns {Promise<void>} A Promise that resolves when the connection has been successfully terminated, or rejects with an error.
                 */
                HubConnection.prototype.stop = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        var startPromise, e_3;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    startPromise = this.startPromise;
                                    this.stopPromise = this.stopInternal();
                                    return [4 /*yield*/, this.stopPromise];
                                case 1:
                                    _a.sent();
                                    _a.label = 2;
                                case 2:
                                    _a.trys.push([2, 4, , 5]);
                                    // Awaiting undefined continues immediately
                                    return [4 /*yield*/, startPromise];
                                case 3:
                                    // Awaiting undefined continues immediately
                                    _a.sent();
                                    return [3 /*break*/, 5];
                                case 4:
                                    e_3 = _a.sent();
                                    return [3 /*break*/, 5];
                                case 5: return [2 /*return*/];
                            }
                        });
                    });
                };
                HubConnection.prototype.stopInternal = function (error) {
                    if (this.connectionState === HubConnectionState.Disconnected) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Call to HubConnection.stop(" + error + ") ignored because it is already in the disconnected state.");
                        return Promise.resolve();
                    }
                    if (this.connectionState === HubConnectionState.Disconnecting) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Call to HttpConnection.stop(" + error + ") ignored because the connection is already in the disconnecting state.");
                        return this.stopPromise;
                    }
                    this.connectionState = HubConnectionState.Disconnecting;
                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Stopping HubConnection.");
                    if (this.reconnectDelayHandle) {
                        // We're in a reconnect delay which means the underlying connection is currently already stopped.
                        // Just clear the handle to stop the reconnect loop (which no one is waiting on thankfully) and
                        // fire the onclose callbacks.
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Connection stopped during reconnect delay. Done reconnecting.");
                        clearTimeout(this.reconnectDelayHandle);
                        this.reconnectDelayHandle = undefined;
                        this.completeClose();
                        return Promise.resolve();
                    }
                    this.cleanupTimeout();
                    this.cleanupPingTimer();
                    this.stopDuringStartError = error || new Error("The connection was stopped before the hub handshake could complete.");
                    // HttpConnection.stop() should not complete until after either HttpConnection.start() fails
                    // or the onclose callback is invoked. The onclose callback will transition the HubConnection
                    // to the disconnected state if need be before HttpConnection.stop() completes.
                    return this.connection.stop(error);
                };
                /** Invokes a streaming hub method on the server using the specified name and arguments.
                 *
                 * @typeparam T The type of the items returned by the server.
                 * @param {string} methodName The name of the server method to invoke.
                 * @param {any[]} args The arguments used to invoke the server method.
                 * @returns {IStreamResult<T>} An object that yields results from the server as they are received.
                 */
                HubConnection.prototype.stream = function (methodName) {
                    var _this = this;
                    var args = [];
                    for (var _i = 1; _i < arguments.length; _i++) {
                        args[_i - 1] = arguments[_i];
                    }
                    var _a = this.replaceStreamingParams(args), streams = _a[0], streamIds = _a[1];
                    var invocationDescriptor = this.createStreamInvocation(methodName, args, streamIds);
                    var promiseQueue;
                    var subject = new _Subject__WEBPACK_IMPORTED_MODULE_3__["Subject"]();
                    subject.cancelCallback = function () {
                        var cancelInvocation = _this.createCancelInvocation(invocationDescriptor.invocationId);
                        delete _this.callbacks[invocationDescriptor.invocationId];
                        return promiseQueue.then(function () {
                            return _this.sendWithProtocol(cancelInvocation);
                        });
                    };
                    this.callbacks[invocationDescriptor.invocationId] = function (invocationEvent, error) {
                        if (error) {
                            subject.error(error);
                            return;
                        }
                        else if (invocationEvent) {
                            // invocationEvent will not be null when an error is not passed to the callback
                            if (invocationEvent.type === _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion) {
                                if (invocationEvent.error) {
                                    subject.error(new Error(invocationEvent.error));
                                }
                                else {
                                    subject.complete();
                                }
                            }
                            else {
                                subject.next((invocationEvent.item));
                            }
                        }
                    };
                    promiseQueue = this.sendWithProtocol(invocationDescriptor)
                        .catch(function (e) {
                            subject.error(e);
                            delete _this.callbacks[invocationDescriptor.invocationId];
                        });
                    this.launchStreams(streams, promiseQueue);
                    return subject;
                };
                HubConnection.prototype.sendMessage = function (message) {
                    this.resetKeepAliveInterval();
                    return this.connection.send(message);
                };
                /**
                 * Sends a js object to the server.
                 * @param message The js object to serialize and send.
                 */
                HubConnection.prototype.sendWithProtocol = function (message) {
                    return this.sendMessage(this.protocol.writeMessage(message));
                };
                /** Invokes a hub method on the server using the specified name and arguments. Does not wait for a response from the receiver.
                 *
                 * The Promise returned by this method resolves when the client has sent the invocation to the server. The server may still
                 * be processing the invocation.
                 *
                 * @param {string} methodName The name of the server method to invoke.
                 * @param {any[]} args The arguments used to invoke the server method.
                 * @returns {Promise<void>} A Promise that resolves when the invocation has been successfully sent, or rejects with an error.
                 */
                HubConnection.prototype.send = function (methodName) {
                    var args = [];
                    for (var _i = 1; _i < arguments.length; _i++) {
                        args[_i - 1] = arguments[_i];
                    }
                    var _a = this.replaceStreamingParams(args), streams = _a[0], streamIds = _a[1];
                    var sendPromise = this.sendWithProtocol(this.createInvocation(methodName, args, true, streamIds));
                    this.launchStreams(streams, sendPromise);
                    return sendPromise;
                };
                /** Invokes a hub method on the server using the specified name and arguments.
                 *
                 * The Promise returned by this method resolves when the server indicates it has finished invoking the method. When the promise
                 * resolves, the server has finished invoking the method. If the server method returns a result, it is produced as the result of
                 * resolving the Promise.
                 *
                 * @typeparam T The expected return type.
                 * @param {string} methodName The name of the server method to invoke.
                 * @param {any[]} args The arguments used to invoke the server method.
                 * @returns {Promise<T>} A Promise that resolves with the result of the server method (if any), or rejects with an error.
                 */
                HubConnection.prototype.invoke = function (methodName) {
                    var _this = this;
                    var args = [];
                    for (var _i = 1; _i < arguments.length; _i++) {
                        args[_i - 1] = arguments[_i];
                    }
                    var _a = this.replaceStreamingParams(args), streams = _a[0], streamIds = _a[1];
                    var invocationDescriptor = this.createInvocation(methodName, args, false, streamIds);
                    var p = new Promise(function (resolve, reject) {
                        // invocationId will always have a value for a non-blocking invocation
                        _this.callbacks[invocationDescriptor.invocationId] = function (invocationEvent, error) {
                            if (error) {
                                reject(error);
                                return;
                            }
                            else if (invocationEvent) {
                                // invocationEvent will not be null when an error is not passed to the callback
                                if (invocationEvent.type === _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion) {
                                    if (invocationEvent.error) {
                                        reject(new Error(invocationEvent.error));
                                    }
                                    else {
                                        resolve(invocationEvent.result);
                                    }
                                }
                                else {
                                    reject(new Error("Unexpected message type: " + invocationEvent.type));
                                }
                            }
                        };
                        var promiseQueue = _this.sendWithProtocol(invocationDescriptor)
                            .catch(function (e) {
                                reject(e);
                                // invocationId will always have a value for a non-blocking invocation
                                delete _this.callbacks[invocationDescriptor.invocationId];
                            });
                        _this.launchStreams(streams, promiseQueue);
                    });
                    return p;
                };
                /** Registers a handler that will be invoked when the hub method with the specified method name is invoked.
                 *
                 * @param {string} methodName The name of the hub method to define.
                 * @param {Function} newMethod The handler that will be raised when the hub method is invoked.
                 */
                HubConnection.prototype.on = function (methodName, newMethod) {
                    if (!methodName || !newMethod) {
                        return;
                    }
                    methodName = methodName.toLowerCase();
                    if (!this.methods[methodName]) {
                        this.methods[methodName] = [];
                    }
                    // Preventing adding the same handler multiple times.
                    if (this.methods[methodName].indexOf(newMethod) !== -1) {
                        return;
                    }
                    this.methods[methodName].push(newMethod);
                };
                HubConnection.prototype.off = function (methodName, method) {
                    if (!methodName) {
                        return;
                    }
                    methodName = methodName.toLowerCase();
                    var handlers = this.methods[methodName];
                    if (!handlers) {
                        return;
                    }
                    if (method) {
                        var removeIdx = handlers.indexOf(method);
                        if (removeIdx !== -1) {
                            handlers.splice(removeIdx, 1);
                            if (handlers.length === 0) {
                                delete this.methods[methodName];
                            }
                        }
                    }
                    else {
                        delete this.methods[methodName];
                    }
                };
                /** Registers a handler that will be invoked when the connection is closed.
                 *
                 * @param {Function} callback The handler that will be invoked when the connection is closed. Optionally receives a single argument containing the error that caused the connection to close (if any).
                 */
                HubConnection.prototype.onclose = function (callback) {
                    if (callback) {
                        this.closedCallbacks.push(callback);
                    }
                };
                /** Registers a handler that will be invoked when the connection starts reconnecting.
                 *
                 * @param {Function} callback The handler that will be invoked when the connection starts reconnecting. Optionally receives a single argument containing the error that caused the connection to start reconnecting (if any).
                 */
                HubConnection.prototype.onreconnecting = function (callback) {
                    if (callback) {
                        this.reconnectingCallbacks.push(callback);
                    }
                };
                /** Registers a handler that will be invoked when the connection successfully reconnects.
                 *
                 * @param {Function} callback The handler that will be invoked when the connection successfully reconnects.
                 */
                HubConnection.prototype.onreconnected = function (callback) {
                    if (callback) {
                        this.reconnectedCallbacks.push(callback);
                    }
                };
                HubConnection.prototype.processIncomingData = function (data) {
                    this.cleanupTimeout();
                    if (!this.receivedHandshakeResponse) {
                        data = this.processHandshakeResponse(data);
                        this.receivedHandshakeResponse = true;
                    }
                    // Data may have all been read when processing handshake response
                    if (data) {
                        // Parse the messages
                        var messages = this.protocol.parseMessages(data, this.logger);
                        for (var _i = 0, messages_1 = messages; _i < messages_1.length; _i++) {
                            var message = messages_1[_i];
                            switch (message.type) {
                                case _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Invocation:
                                    this.invokeClientMethod(message);
                                    break;
                                case _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].StreamItem:
                                case _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion:
                                    var callback = this.callbacks[message.invocationId];
                                    if (callback) {
                                        if (message.type === _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion) {
                                            delete this.callbacks[message.invocationId];
                                        }
                                        callback(message);
                                    }
                                    break;
                                case _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Ping:
                                    // Don't care about pings
                                    break;
                                case _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Close:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Close message received from server.");
                                    var error = message.error ? new Error("Server returned an error on close: " + message.error) : undefined;
                                    if (message.allowReconnect === true) {
                                        // It feels wrong not to await connection.stop() here, but processIncomingData is called as part of an onreceive callback which is not async,
                                        // this is already the behavior for serverTimeout(), and HttpConnection.Stop() should catch and log all possible exceptions.
                                        // tslint:disable-next-line:no-floating-promises
                                        this.connection.stop(error);
                                    }
                                    else {
                                        // We cannot await stopInternal() here, but subsequent calls to stop() will await this if stopInternal() is still ongoing.
                                        this.stopPromise = this.stopInternal(error);
                                    }
                                    break;
                                default:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "Invalid message type: " + message.type + ".");
                                    break;
                            }
                        }
                    }
                    this.resetTimeoutPeriod();
                };
                HubConnection.prototype.processHandshakeResponse = function (data) {
                    var _a;
                    var responseMessage;
                    var remainingData;
                    try {
                        _a = this.handshakeProtocol.parseHandshakeResponse(data), remainingData = _a[0], responseMessage = _a[1];
                    }
                    catch (e) {
                        var message = "Error parsing handshake response: " + e;
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, message);
                        var error = new Error(message);
                        this.handshakeRejecter(error);
                        throw error;
                    }
                    if (responseMessage.error) {
                        var message = "Server returned handshake error: " + responseMessage.error;
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, message);
                        var error = new Error(message);
                        this.handshakeRejecter(error);
                        throw error;
                    }
                    else {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Server handshake complete.");
                    }
                    this.handshakeResolver();
                    return remainingData;
                };
                HubConnection.prototype.resetKeepAliveInterval = function () {
                    var _this = this;
                    this.cleanupPingTimer();
                    this.pingServerHandle = setTimeout(function () {
                        return __awaiter(_this, void 0, void 0, function () {
                            var _a;
                            return __generator(this, function (_b) {
                                switch (_b.label) {
                                    case 0:
                                        if (!(this.connectionState === HubConnectionState.Connected)) return [3 /*break*/, 4];
                                        _b.label = 1;
                                    case 1:
                                        _b.trys.push([1, 3, , 4]);
                                        return [4 /*yield*/, this.sendMessage(this.cachedPingMessage)];
                                    case 2:
                                        _b.sent();
                                        return [3 /*break*/, 4];
                                    case 3:
                                        _a = _b.sent();
                                        // We don't care about the error. It should be seen elsewhere in the client.
                                        // The connection is probably in a bad or closed state now, cleanup the timer so it stops triggering
                                        this.cleanupPingTimer();
                                        return [3 /*break*/, 4];
                                    case 4: return [2 /*return*/];
                                }
                            });
                        });
                    }, this.keepAliveIntervalInMilliseconds);
                };
                HubConnection.prototype.resetTimeoutPeriod = function () {
                    var _this = this;
                    if (!this.connection.features || !this.connection.features.inherentKeepAlive) {
                        // Set the timeout timer
                        this.timeoutHandle = setTimeout(function () { return _this.serverTimeout(); }, this.serverTimeoutInMilliseconds);
                    }
                };
                HubConnection.prototype.serverTimeout = function () {
                    // The server hasn't talked to us in a while. It doesn't like us anymore ... :(
                    // Terminate the connection, but we don't need to wait on the promise. This could trigger reconnecting.
                    // tslint:disable-next-line:no-floating-promises
                    this.connection.stop(new Error("Server timeout elapsed without receiving a message from the server."));
                };
                HubConnection.prototype.invokeClientMethod = function (invocationMessage) {
                    var _this = this;
                    var methods = this.methods[invocationMessage.target.toLowerCase()];
                    if (methods) {
                        try {
                            methods.forEach(function (m) { return m.apply(_this, invocationMessage.arguments); });
                        }
                        catch (e) {
                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "A callback for the method " + invocationMessage.target.toLowerCase() + " threw error '" + e + "'.");
                        }
                        if (invocationMessage.invocationId) {
                            // This is not supported in v1. So we return an error to avoid blocking the server waiting for the response.
                            var message = "Server requested a response, which is not supported in this version of the client.";
                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, message);
                            // We don't want to wait on the stop itself.
                            this.stopPromise = this.stopInternal(new Error(message));
                        }
                    }
                    else {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "No client method with the name '" + invocationMessage.target + "' found.");
                    }
                };
                HubConnection.prototype.connectionClosed = function (error) {
                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "HubConnection.connectionClosed(" + error + ") called while in state " + this.connectionState + ".");
                    // Triggering this.handshakeRejecter is insufficient because it could already be resolved without the continuation having run yet.
                    this.stopDuringStartError = this.stopDuringStartError || error || new Error("The underlying connection was closed before the hub handshake could complete.");
                    // If the handshake is in progress, start will be waiting for the handshake promise, so we complete it.
                    // If it has already completed, this should just noop.
                    if (this.handshakeResolver) {
                        this.handshakeResolver();
                    }
                    this.cancelCallbacksWithError(error || new Error("Invocation canceled due to the underlying connection being closed."));
                    this.cleanupTimeout();
                    this.cleanupPingTimer();
                    if (this.connectionState === HubConnectionState.Disconnecting) {
                        this.completeClose(error);
                    }
                    else if (this.connectionState === HubConnectionState.Connected && this.reconnectPolicy) {
                        // tslint:disable-next-line:no-floating-promises
                        this.reconnect(error);
                    }
                    else if (this.connectionState === HubConnectionState.Connected) {
                        this.completeClose(error);
                    }
                    // If none of the above if conditions were true were called the HubConnection must be in either:
                    // 1. The Connecting state in which case the handshakeResolver will complete it and stopDuringStartError will fail it.
                    // 2. The Reconnecting state in which case the handshakeResolver will complete it and stopDuringStartError will fail the current reconnect attempt
                    //    and potentially continue the reconnect() loop.
                    // 3. The Disconnected state in which case we're already done.
                };
                HubConnection.prototype.completeClose = function (error) {
                    var _this = this;
                    if (this.connectionStarted) {
                        this.connectionState = HubConnectionState.Disconnected;
                        this.connectionStarted = false;
                        try {
                            this.closedCallbacks.forEach(function (c) { return c.apply(_this, [error]); });
                        }
                        catch (e) {
                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "An onclose callback called with error '" + error + "' threw error '" + e + "'.");
                        }
                    }
                };
                HubConnection.prototype.reconnect = function (error) {
                    return __awaiter(this, void 0, void 0, function () {
                        var reconnectStartTime, previousReconnectAttempts, retryError, nextRetryDelay, e_4;
                        var _this = this;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    reconnectStartTime = Date.now();
                                    previousReconnectAttempts = 0;
                                    retryError = error !== undefined ? error : new Error("Attempting to reconnect due to a unknown error.");
                                    nextRetryDelay = this.getNextRetryDelay(previousReconnectAttempts++, 0, retryError);
                                    if (nextRetryDelay === null) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Connection not reconnecting because the IRetryPolicy returned null on the first reconnect attempt.");
                                        this.completeClose(error);
                                        return [2 /*return*/];
                                    }
                                    this.connectionState = HubConnectionState.Reconnecting;
                                    if (error) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Connection reconnecting because of error '" + error + "'.");
                                    }
                                    else {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Connection reconnecting.");
                                    }
                                    if (this.onreconnecting) {
                                        try {
                                            this.reconnectingCallbacks.forEach(function (c) { return c.apply(_this, [error]); });
                                        }
                                        catch (e) {
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "An onreconnecting callback called with error '" + error + "' threw error '" + e + "'.");
                                        }
                                        // Exit early if an onreconnecting callback called connection.stop().
                                        if (this.connectionState !== HubConnectionState.Reconnecting) {
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Connection left the reconnecting state in onreconnecting callback. Done reconnecting.");
                                            return [2 /*return*/];
                                        }
                                    }
                                    _a.label = 1;
                                case 1:
                                    if (!(nextRetryDelay !== null)) return [3 /*break*/, 7];
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Reconnect attempt number " + previousReconnectAttempts + " will start in " + nextRetryDelay + " ms.");
                                    return [4 /*yield*/, new Promise(function (resolve) {
                                        _this.reconnectDelayHandle = setTimeout(resolve, nextRetryDelay);
                                    })];
                                case 2:
                                    _a.sent();
                                    this.reconnectDelayHandle = undefined;
                                    if (this.connectionState !== HubConnectionState.Reconnecting) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Connection left the reconnecting state during reconnect delay. Done reconnecting.");
                                        return [2 /*return*/];
                                    }
                                    _a.label = 3;
                                case 3:
                                    _a.trys.push([3, 5, , 6]);
                                    return [4 /*yield*/, this.startInternal()];
                                case 4:
                                    _a.sent();
                                    this.connectionState = HubConnectionState.Connected;
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "HubConnection reconnected successfully.");
                                    if (this.onreconnected) {
                                        try {
                                            this.reconnectedCallbacks.forEach(function (c) { return c.apply(_this, [_this.connection.connectionId]); });
                                        }
                                        catch (e) {
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "An onreconnected callback called with connectionId '" + this.connection.connectionId + "; threw error '" + e + "'.");
                                        }
                                    }
                                    return [2 /*return*/];
                                case 5:
                                    e_4 = _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Reconnect attempt failed because of error '" + e_4 + "'.");
                                    if (this.connectionState !== HubConnectionState.Reconnecting) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Debug, "Connection left the reconnecting state during reconnect attempt. Done reconnecting.");
                                        return [2 /*return*/];
                                    }
                                    retryError = e_4 instanceof Error ? e_4 : new Error(e_4.toString());
                                    nextRetryDelay = this.getNextRetryDelay(previousReconnectAttempts++, Date.now() - reconnectStartTime, retryError);
                                    return [3 /*break*/, 6];
                                case 6: return [3 /*break*/, 1];
                                case 7:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "Reconnect retries have been exhausted after " + (Date.now() - reconnectStartTime) + " ms and " + previousReconnectAttempts + " failed attempts. Connection disconnecting.");
                                    this.completeClose();
                                    return [2 /*return*/];
                            }
                        });
                    });
                };
                HubConnection.prototype.getNextRetryDelay = function (previousRetryCount, elapsedMilliseconds, retryReason) {
                    try {
                        return this.reconnectPolicy.nextRetryDelayInMilliseconds({
                            elapsedMilliseconds: elapsedMilliseconds,
                            previousRetryCount: previousRetryCount,
                            retryReason: retryReason,
                        });
                    }
                    catch (e) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "IRetryPolicy.nextRetryDelayInMilliseconds(" + previousRetryCount + ", " + elapsedMilliseconds + ") threw error '" + e + "'.");
                        return null;
                    }
                };
                HubConnection.prototype.cancelCallbacksWithError = function (error) {
                    var callbacks = this.callbacks;
                    this.callbacks = {};
                    Object.keys(callbacks)
                        .forEach(function (key) {
                            var callback = callbacks[key];
                            callback(null, error);
                        });
                };
                HubConnection.prototype.cleanupPingTimer = function () {
                    if (this.pingServerHandle) {
                        clearTimeout(this.pingServerHandle);
                    }
                };
                HubConnection.prototype.cleanupTimeout = function () {
                    if (this.timeoutHandle) {
                        clearTimeout(this.timeoutHandle);
                    }
                };
                HubConnection.prototype.createInvocation = function (methodName, args, nonblocking, streamIds) {
                    if (nonblocking) {
                        return {
                            arguments: args,
                            streamIds: streamIds,
                            target: methodName,
                            type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Invocation,
                        };
                    }
                    else {
                        var invocationId = this.invocationId;
                        this.invocationId++;
                        return {
                            arguments: args,
                            invocationId: invocationId.toString(),
                            streamIds: streamIds,
                            target: methodName,
                            type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Invocation,
                        };
                    }
                };
                HubConnection.prototype.launchStreams = function (streams, promiseQueue) {
                    var _this = this;
                    if (streams.length === 0) {
                        return;
                    }
                    // Synchronize stream data so they arrive in-order on the server
                    if (!promiseQueue) {
                        promiseQueue = Promise.resolve();
                    }
                    var _loop_1 = function (streamId) {
                        streams[streamId].subscribe({
                            complete: function () {
                                promiseQueue = promiseQueue.then(function () { return _this.sendWithProtocol(_this.createCompletionMessage(streamId)); });
                            },
                            error: function (err) {
                                var message;
                                if (err instanceof Error) {
                                    message = err.message;
                                }
                                else if (err && err.toString) {
                                    message = err.toString();
                                }
                                else {
                                    message = "Unknown error";
                                }
                                promiseQueue = promiseQueue.then(function () { return _this.sendWithProtocol(_this.createCompletionMessage(streamId, message)); });
                            },
                            next: function (item) {
                                promiseQueue = promiseQueue.then(function () { return _this.sendWithProtocol(_this.createStreamItemMessage(streamId, item)); });
                            },
                        });
                    };
                    // We want to iterate over the keys, since the keys are the stream ids
                    // tslint:disable-next-line:forin
                    for (var streamId in streams) {
                        _loop_1(streamId);
                    }
                };
                HubConnection.prototype.replaceStreamingParams = function (args) {
                    var streams = [];
                    var streamIds = [];
                    for (var i = 0; i < args.length; i++) {
                        var argument = args[i];
                        if (this.isObservable(argument)) {
                            var streamId = this.invocationId;
                            this.invocationId++;
                            // Store the stream for later use
                            streams[streamId] = argument;
                            streamIds.push(streamId.toString());
                            // remove stream from args
                            args.splice(i, 1);
                        }
                    }
                    return [streams, streamIds];
                };
                HubConnection.prototype.isObservable = function (arg) {
                    // This allows other stream implementations to just work (like rxjs)
                    return arg && arg.subscribe && typeof arg.subscribe === "function";
                };
                HubConnection.prototype.createStreamInvocation = function (methodName, args, streamIds) {
                    var invocationId = this.invocationId;
                    this.invocationId++;
                    return {
                        arguments: args,
                        invocationId: invocationId.toString(),
                        streamIds: streamIds,
                        target: methodName,
                        type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].StreamInvocation,
                    };
                };
                HubConnection.prototype.createCancelInvocation = function (id) {
                    return {
                        invocationId: id,
                        type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].CancelInvocation,
                    };
                };
                HubConnection.prototype.createStreamItemMessage = function (id, item) {
                    return {
                        invocationId: id,
                        item: item,
                        type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].StreamItem,
                    };
                };
                HubConnection.prototype.createCompletionMessage = function (id, error, result) {
                    if (error) {
                        return {
                            error: error,
                            invocationId: id,
                            type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion,
                        };
                    }
                    return {
                        invocationId: id,
                        result: result,
                        type: _IHubProtocol__WEBPACK_IMPORTED_MODULE_1__["MessageType"].Completion,
                    };
                };
                return HubConnection;
            }());

            //# sourceMappingURL=HubConnection.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/HubConnectionBuilder.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/HubConnectionBuilder.js ***!
  \**************************************************************************/
/*! exports provided: HubConnectionBuilder */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HubConnectionBuilder", function () { return HubConnectionBuilder; });
/* harmony import */ var _DefaultReconnectPolicy__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./DefaultReconnectPolicy */ "./node_modules/@microsoft/signalr/dist/esm/DefaultReconnectPolicy.js");
/* harmony import */ var _HttpConnection__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./HttpConnection */ "./node_modules/@microsoft/signalr/dist/esm/HttpConnection.js");
/* harmony import */ var _HubConnection__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./HubConnection */ "./node_modules/@microsoft/signalr/dist/esm/HubConnection.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _JsonHubProtocol__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./JsonHubProtocol */ "./node_modules/@microsoft/signalr/dist/esm/JsonHubProtocol.js");
/* harmony import */ var _Loggers__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./Loggers */ "./node_modules/@microsoft/signalr/dist/esm/Loggers.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __assign = (undefined && undefined.__assign) || Object.assign || function (t) {
                for (var s, i = 1, n = arguments.length; i < n; i++) {
                    s = arguments[i];
                    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                        t[p] = s[p];
                }
                return t;
            };







            // tslint:disable:object-literal-sort-keys
            var LogLevelNameMapping = {
                trace: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Trace,
                debug: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Debug,
                info: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Information,
                information: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Information,
                warn: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Warning,
                warning: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Warning,
                error: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Error,
                critical: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].Critical,
                none: _ILogger__WEBPACK_IMPORTED_MODULE_3__["LogLevel"].None,
            };
            function parseLogLevel(name) {
                // Case-insensitive matching via lower-casing
                // Yes, I know case-folding is a complicated problem in Unicode, but we only support
                // the ASCII strings defined in LogLevelNameMapping anyway, so it's fine -anurse.
                var mapping = LogLevelNameMapping[name.toLowerCase()];
                if (typeof mapping !== "undefined") {
                    return mapping;
                }
                else {
                    throw new Error("Unknown log level: " + name);
                }
            }
            /** A builder for configuring {@link @microsoft/signalr.HubConnection} instances. */
            var HubConnectionBuilder = /** @class */ (function () {
                function HubConnectionBuilder() {
                }
                HubConnectionBuilder.prototype.configureLogging = function (logging) {
                    _Utils__WEBPACK_IMPORTED_MODULE_6__["Arg"].isRequired(logging, "logging");
                    if (isLogger(logging)) {
                        this.logger = logging;
                    }
                    else if (typeof logging === "string") {
                        var logLevel = parseLogLevel(logging);
                        this.logger = new _Utils__WEBPACK_IMPORTED_MODULE_6__["ConsoleLogger"](logLevel);
                    }
                    else {
                        this.logger = new _Utils__WEBPACK_IMPORTED_MODULE_6__["ConsoleLogger"](logging);
                    }
                    return this;
                };
                HubConnectionBuilder.prototype.withUrl = function (url, transportTypeOrOptions) {
                    _Utils__WEBPACK_IMPORTED_MODULE_6__["Arg"].isRequired(url, "url");
                    this.url = url;
                    // Flow-typing knows where it's at. Since HttpTransportType is a number and IHttpConnectionOptions is guaranteed
                    // to be an object, we know (as does TypeScript) this comparison is all we need to figure out which overload was called.
                    if (typeof transportTypeOrOptions === "object") {
                        this.httpConnectionOptions = __assign({}, this.httpConnectionOptions, transportTypeOrOptions);
                    }
                    else {
                        this.httpConnectionOptions = __assign({}, this.httpConnectionOptions, { transport: transportTypeOrOptions });
                    }
                    return this;
                };
                /** Configures the {@link @microsoft/signalr.HubConnection} to use the specified Hub Protocol.
                 *
                 * @param {IHubProtocol} protocol The {@link @microsoft/signalr.IHubProtocol} implementation to use.
                 */
                HubConnectionBuilder.prototype.withHubProtocol = function (protocol) {
                    _Utils__WEBPACK_IMPORTED_MODULE_6__["Arg"].isRequired(protocol, "protocol");
                    this.protocol = protocol;
                    return this;
                };
                HubConnectionBuilder.prototype.withAutomaticReconnect = function (retryDelaysOrReconnectPolicy) {
                    if (this.reconnectPolicy) {
                        throw new Error("A reconnectPolicy has already been set.");
                    }
                    if (!retryDelaysOrReconnectPolicy) {
                        this.reconnectPolicy = new _DefaultReconnectPolicy__WEBPACK_IMPORTED_MODULE_0__["DefaultReconnectPolicy"]();
                    }
                    else if (Array.isArray(retryDelaysOrReconnectPolicy)) {
                        this.reconnectPolicy = new _DefaultReconnectPolicy__WEBPACK_IMPORTED_MODULE_0__["DefaultReconnectPolicy"](retryDelaysOrReconnectPolicy);
                    }
                    else {
                        this.reconnectPolicy = retryDelaysOrReconnectPolicy;
                    }
                    return this;
                };
                /** Creates a {@link @microsoft/signalr.HubConnection} from the configuration options specified in this builder.
                 *
                 * @returns {HubConnection} The configured {@link @microsoft/signalr.HubConnection}.
                 */
                HubConnectionBuilder.prototype.build = function () {
                    // If httpConnectionOptions has a logger, use it. Otherwise, override it with the one
                    // provided to configureLogger
                    var httpConnectionOptions = this.httpConnectionOptions || {};
                    // If it's 'null', the user **explicitly** asked for null, don't mess with it.
                    if (httpConnectionOptions.logger === undefined) {
                        // If our logger is undefined or null, that's OK, the HttpConnection constructor will handle it.
                        httpConnectionOptions.logger = this.logger;
                    }
                    // Now create the connection
                    if (!this.url) {
                        throw new Error("The 'HubConnectionBuilder.withUrl' method must be called before building the connection.");
                    }
                    var connection = new _HttpConnection__WEBPACK_IMPORTED_MODULE_1__["HttpConnection"](this.url, httpConnectionOptions);
                    return _HubConnection__WEBPACK_IMPORTED_MODULE_2__["HubConnection"].create(connection, this.logger || _Loggers__WEBPACK_IMPORTED_MODULE_5__["NullLogger"].instance, this.protocol || new _JsonHubProtocol__WEBPACK_IMPORTED_MODULE_4__["JsonHubProtocol"](), this.reconnectPolicy);
                };
                return HubConnectionBuilder;
            }());

            function isLogger(logger) {
                return logger.log !== undefined;
            }
            //# sourceMappingURL=HubConnectionBuilder.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/IHubProtocol.js":
/*!******************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/IHubProtocol.js ***!
  \******************************************************************/
/*! exports provided: MessageType */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "MessageType", function () { return MessageType; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            /** Defines the type of a Hub Message. */
            var MessageType;
            (function (MessageType) {
                /** Indicates the message is an Invocation message and implements the {@link @microsoft/signalr.InvocationMessage} interface. */
                MessageType[MessageType["Invocation"] = 1] = "Invocation";
                /** Indicates the message is a StreamItem message and implements the {@link @microsoft/signalr.StreamItemMessage} interface. */
                MessageType[MessageType["StreamItem"] = 2] = "StreamItem";
                /** Indicates the message is a Completion message and implements the {@link @microsoft/signalr.CompletionMessage} interface. */
                MessageType[MessageType["Completion"] = 3] = "Completion";
                /** Indicates the message is a Stream Invocation message and implements the {@link @microsoft/signalr.StreamInvocationMessage} interface. */
                MessageType[MessageType["StreamInvocation"] = 4] = "StreamInvocation";
                /** Indicates the message is a Cancel Invocation message and implements the {@link @microsoft/signalr.CancelInvocationMessage} interface. */
                MessageType[MessageType["CancelInvocation"] = 5] = "CancelInvocation";
                /** Indicates the message is a Ping message and implements the {@link @microsoft/signalr.PingMessage} interface. */
                MessageType[MessageType["Ping"] = 6] = "Ping";
                /** Indicates the message is a Close message and implements the {@link @microsoft/signalr.CloseMessage} interface. */
                MessageType[MessageType["Close"] = 7] = "Close";
            })(MessageType || (MessageType = {}));
            //# sourceMappingURL=IHubProtocol.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js":
/*!*************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/ILogger.js ***!
  \*************************************************************/
/*! exports provided: LogLevel */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "LogLevel", function () { return LogLevel; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // These values are designed to match the ASP.NET Log Levels since that's the pattern we're emulating here.
            /** Indicates the severity of a log message.
             *
             * Log Levels are ordered in increasing severity. So `Debug` is more severe than `Trace`, etc.
             */
            var LogLevel;
            (function (LogLevel) {
                /** Log level for very low severity diagnostic messages. */
                LogLevel[LogLevel["Trace"] = 0] = "Trace";
                /** Log level for low severity diagnostic messages. */
                LogLevel[LogLevel["Debug"] = 1] = "Debug";
                /** Log level for informational diagnostic messages. */
                LogLevel[LogLevel["Information"] = 2] = "Information";
                /** Log level for diagnostic messages that indicate a non-fatal problem. */
                LogLevel[LogLevel["Warning"] = 3] = "Warning";
                /** Log level for diagnostic messages that indicate a failure in the current operation. */
                LogLevel[LogLevel["Error"] = 4] = "Error";
                /** Log level for diagnostic messages that indicate a failure that will terminate the entire application. */
                LogLevel[LogLevel["Critical"] = 5] = "Critical";
                /** The highest possible log level. Used when configuring logging to indicate that no log messages should be emitted. */
                LogLevel[LogLevel["None"] = 6] = "None";
            })(LogLevel || (LogLevel = {}));
            //# sourceMappingURL=ILogger.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js":
/*!****************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/ITransport.js ***!
  \****************************************************************/
/*! exports provided: HttpTransportType, TransferFormat */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HttpTransportType", function () { return HttpTransportType; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "TransferFormat", function () { return TransferFormat; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // This will be treated as a bit flag in the future, so we keep it using power-of-two values.
            /** Specifies a specific HTTP transport type. */
            var HttpTransportType;
            (function (HttpTransportType) {
                /** Specifies no transport preference. */
                HttpTransportType[HttpTransportType["None"] = 0] = "None";
                /** Specifies the WebSockets transport. */
                HttpTransportType[HttpTransportType["WebSockets"] = 1] = "WebSockets";
                /** Specifies the Server-Sent Events transport. */
                HttpTransportType[HttpTransportType["ServerSentEvents"] = 2] = "ServerSentEvents";
                /** Specifies the Long Polling transport. */
                HttpTransportType[HttpTransportType["LongPolling"] = 4] = "LongPolling";
            })(HttpTransportType || (HttpTransportType = {}));
            /** Specifies the transfer format for a connection. */
            var TransferFormat;
            (function (TransferFormat) {
                /** Specifies that only text data will be transmitted over the connection. */
                TransferFormat[TransferFormat["Text"] = 1] = "Text";
                /** Specifies that binary data will be transmitted over the connection. */
                TransferFormat[TransferFormat["Binary"] = 2] = "Binary";
            })(TransferFormat || (TransferFormat = {}));
            //# sourceMappingURL=ITransport.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/JsonHubProtocol.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/JsonHubProtocol.js ***!
  \*********************************************************************/
/*! exports provided: JsonHubProtocol */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "JsonHubProtocol", function () { return JsonHubProtocol; });
/* harmony import */ var _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./IHubProtocol */ "./node_modules/@microsoft/signalr/dist/esm/IHubProtocol.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony import */ var _Loggers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Loggers */ "./node_modules/@microsoft/signalr/dist/esm/Loggers.js");
/* harmony import */ var _TextMessageFormat__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./TextMessageFormat */ "./node_modules/@microsoft/signalr/dist/esm/TextMessageFormat.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.





            var JSON_HUB_PROTOCOL_NAME = "json";
            /** Implements the JSON Hub Protocol. */
            var JsonHubProtocol = /** @class */ (function () {
                function JsonHubProtocol() {
                    /** @inheritDoc */
                    this.name = JSON_HUB_PROTOCOL_NAME;
                    /** @inheritDoc */
                    this.version = 1;
                    /** @inheritDoc */
                    this.transferFormat = _ITransport__WEBPACK_IMPORTED_MODULE_2__["TransferFormat"].Text;
                }
                /** Creates an array of {@link @microsoft/signalr.HubMessage} objects from the specified serialized representation.
                 *
                 * @param {string} input A string containing the serialized representation.
                 * @param {ILogger} logger A logger that will be used to log messages that occur during parsing.
                 */
                JsonHubProtocol.prototype.parseMessages = function (input, logger) {
                    // The interface does allow "ArrayBuffer" to be passed in, but this implementation does not. So let's throw a useful error.
                    if (typeof input !== "string") {
                        throw new Error("Invalid input for JSON hub protocol. Expected a string.");
                    }
                    if (!input) {
                        return [];
                    }
                    if (logger === null) {
                        logger = _Loggers__WEBPACK_IMPORTED_MODULE_3__["NullLogger"].instance;
                    }
                    // Parse the messages
                    var messages = _TextMessageFormat__WEBPACK_IMPORTED_MODULE_4__["TextMessageFormat"].parse(input);
                    var hubMessages = [];
                    for (var _i = 0, messages_1 = messages; _i < messages_1.length; _i++) {
                        var message = messages_1[_i];
                        var parsedMessage = JSON.parse(message);
                        if (typeof parsedMessage.type !== "number") {
                            throw new Error("Invalid payload.");
                        }
                        switch (parsedMessage.type) {
                            case _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__["MessageType"].Invocation:
                                this.isInvocationMessage(parsedMessage);
                                break;
                            case _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__["MessageType"].StreamItem:
                                this.isStreamItemMessage(parsedMessage);
                                break;
                            case _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__["MessageType"].Completion:
                                this.isCompletionMessage(parsedMessage);
                                break;
                            case _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__["MessageType"].Ping:
                                // Single value, no need to validate
                                break;
                            case _IHubProtocol__WEBPACK_IMPORTED_MODULE_0__["MessageType"].Close:
                                // All optional values, no need to validate
                                break;
                            default:
                                // Future protocol changes can add message types, old clients can ignore them
                                logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_1__["LogLevel"].Information, "Unknown message type '" + parsedMessage.type + "' ignored.");
                                continue;
                        }
                        hubMessages.push(parsedMessage);
                    }
                    return hubMessages;
                };
                /** Writes the specified {@link @microsoft/signalr.HubMessage} to a string and returns it.
                 *
                 * @param {HubMessage} message The message to write.
                 * @returns {string} A string containing the serialized representation of the message.
                 */
                JsonHubProtocol.prototype.writeMessage = function (message) {
                    return _TextMessageFormat__WEBPACK_IMPORTED_MODULE_4__["TextMessageFormat"].write(JSON.stringify(message));
                };
                JsonHubProtocol.prototype.isInvocationMessage = function (message) {
                    this.assertNotEmptyString(message.target, "Invalid payload for Invocation message.");
                    if (message.invocationId !== undefined) {
                        this.assertNotEmptyString(message.invocationId, "Invalid payload for Invocation message.");
                    }
                };
                JsonHubProtocol.prototype.isStreamItemMessage = function (message) {
                    this.assertNotEmptyString(message.invocationId, "Invalid payload for StreamItem message.");
                    if (message.item === undefined) {
                        throw new Error("Invalid payload for StreamItem message.");
                    }
                };
                JsonHubProtocol.prototype.isCompletionMessage = function (message) {
                    if (message.result && message.error) {
                        throw new Error("Invalid payload for Completion message.");
                    }
                    if (!message.result && message.error) {
                        this.assertNotEmptyString(message.error, "Invalid payload for Completion message.");
                    }
                    this.assertNotEmptyString(message.invocationId, "Invalid payload for Completion message.");
                };
                JsonHubProtocol.prototype.assertNotEmptyString = function (value, errorMessage) {
                    if (typeof value !== "string" || value === "") {
                        throw new Error(errorMessage);
                    }
                };
                return JsonHubProtocol;
            }());

            //# sourceMappingURL=JsonHubProtocol.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/Loggers.js":
/*!*************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/Loggers.js ***!
  \*************************************************************/
/*! exports provided: NullLogger */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "NullLogger", function () { return NullLogger; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            /** A logger that does nothing when log messages are sent to it. */
            var NullLogger = /** @class */ (function () {
                function NullLogger() {
                }
                /** @inheritDoc */
                // tslint:disable-next-line
                NullLogger.prototype.log = function (_logLevel, _message) {
                };
                /** The singleton instance of the {@link @microsoft/signalr.NullLogger}. */
                NullLogger.instance = new NullLogger();
                return NullLogger;
            }());

            //# sourceMappingURL=Loggers.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/LongPollingTransport.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/LongPollingTransport.js ***!
  \**************************************************************************/
/*! exports provided: LongPollingTransport */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "LongPollingTransport", function () { return LongPollingTransport; });
/* harmony import */ var _AbortController__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./AbortController */ "./node_modules/@microsoft/signalr/dist/esm/AbortController.js");
/* harmony import */ var _Errors__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Errors */ "./node_modules/@microsoft/signalr/dist/esm/Errors.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };





            // Not exported from 'index', this type is internal.
            /** @private */
            var LongPollingTransport = /** @class */ (function () {
                function LongPollingTransport(httpClient, accessTokenFactory, logger, logMessageContent) {
                    this.httpClient = httpClient;
                    this.accessTokenFactory = accessTokenFactory;
                    this.logger = logger;
                    this.pollAbort = new _AbortController__WEBPACK_IMPORTED_MODULE_0__["AbortController"]();
                    this.logMessageContent = logMessageContent;
                    this.running = false;
                    this.onreceive = null;
                    this.onclose = null;
                }
                Object.defineProperty(LongPollingTransport.prototype, "pollAborted", {
                    // This is an internal type, not exported from 'index' so this is really just internal.
                    get: function () {
                        return this.pollAbort.aborted;
                    },
                    enumerable: true,
                    configurable: true
                });
                LongPollingTransport.prototype.connect = function (url, transferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var pollOptions, token, pollUrl, response;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isRequired(url, "url");
                                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isRequired(transferFormat, "transferFormat");
                                    _Utils__WEBPACK_IMPORTED_MODULE_4__["Arg"].isIn(transferFormat, _ITransport__WEBPACK_IMPORTED_MODULE_3__["TransferFormat"], "transferFormat");
                                    this.url = url;
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Connecting.");
                                    // Allow binary format on Node and Browsers that support binary content (indicated by the presence of responseType property)
                                    if (transferFormat === _ITransport__WEBPACK_IMPORTED_MODULE_3__["TransferFormat"].Binary &&
                                        (typeof XMLHttpRequest !== "undefined" && typeof new XMLHttpRequest().responseType !== "string")) {
                                        throw new Error("Binary protocols over XmlHttpRequest not implementing advanced features are not supported.");
                                    }
                                    pollOptions = {
                                        abortSignal: this.pollAbort.signal,
                                        headers: {},
                                        timeout: 100000,
                                    };
                                    if (transferFormat === _ITransport__WEBPACK_IMPORTED_MODULE_3__["TransferFormat"].Binary) {
                                        pollOptions.responseType = "arraybuffer";
                                    }
                                    return [4 /*yield*/, this.getAccessToken()];
                                case 1:
                                    token = _a.sent();
                                    this.updateHeaderToken(pollOptions, token);
                                    pollUrl = url + "&_=" + Date.now();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) polling: " + pollUrl + ".");
                                    return [4 /*yield*/, this.httpClient.get(pollUrl, pollOptions)];
                                case 2:
                                    response = _a.sent();
                                    if (response.statusCode !== 200) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "(LongPolling transport) Unexpected response code: " + response.statusCode + ".");
                                        // Mark running as false so that the poll immediately ends and runs the close logic
                                        this.closeError = new _Errors__WEBPACK_IMPORTED_MODULE_1__["HttpError"](response.statusText || "", response.statusCode);
                                        this.running = false;
                                    }
                                    else {
                                        this.running = true;
                                    }
                                    this.receiving = this.poll(this.url, pollOptions);
                                    return [2 /*return*/];
                            }
                        });
                    });
                };
                LongPollingTransport.prototype.getAccessToken = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    if (!this.accessTokenFactory) return [3 /*break*/, 2];
                                    return [4 /*yield*/, this.accessTokenFactory()];
                                case 1: return [2 /*return*/, _a.sent()];
                                case 2: return [2 /*return*/, null];
                            }
                        });
                    });
                };
                LongPollingTransport.prototype.updateHeaderToken = function (request, token) {
                    if (!request.headers) {
                        request.headers = {};
                    }
                    if (token) {
                        // tslint:disable-next-line:no-string-literal
                        request.headers["Authorization"] = "Bearer " + token;
                        return;
                    }
                    // tslint:disable-next-line:no-string-literal
                    if (request.headers["Authorization"]) {
                        // tslint:disable-next-line:no-string-literal
                        delete request.headers["Authorization"];
                    }
                };
                LongPollingTransport.prototype.poll = function (url, pollOptions) {
                    return __awaiter(this, void 0, void 0, function () {
                        var token, pollUrl, response, e_1;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    _a.trys.push([0, , 8, 9]);
                                    _a.label = 1;
                                case 1:
                                    if (!this.running) return [3 /*break*/, 7];
                                    return [4 /*yield*/, this.getAccessToken()];
                                case 2:
                                    token = _a.sent();
                                    this.updateHeaderToken(pollOptions, token);
                                    _a.label = 3;
                                case 3:
                                    _a.trys.push([3, 5, , 6]);
                                    pollUrl = url + "&_=" + Date.now();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) polling: " + pollUrl + ".");
                                    return [4 /*yield*/, this.httpClient.get(pollUrl, pollOptions)];
                                case 4:
                                    response = _a.sent();
                                    if (response.statusCode === 204) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Information, "(LongPolling transport) Poll terminated by server.");
                                        this.running = false;
                                    }
                                    else if (response.statusCode !== 200) {
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Error, "(LongPolling transport) Unexpected response code: " + response.statusCode + ".");
                                        // Unexpected status code
                                        this.closeError = new _Errors__WEBPACK_IMPORTED_MODULE_1__["HttpError"](response.statusText || "", response.statusCode);
                                        this.running = false;
                                    }
                                    else {
                                        // Process the response
                                        if (response.content) {
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) data received. " + Object(_Utils__WEBPACK_IMPORTED_MODULE_4__["getDataDetail"])(response.content, this.logMessageContent) + ".");
                                            if (this.onreceive) {
                                                this.onreceive(response.content);
                                            }
                                        }
                                        else {
                                            // This is another way timeout manifest.
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Poll timed out, reissuing.");
                                        }
                                    }
                                    return [3 /*break*/, 6];
                                case 5:
                                    e_1 = _a.sent();
                                    if (!this.running) {
                                        // Log but disregard errors that occur after stopping
                                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Poll errored after shutdown: " + e_1.message);
                                    }
                                    else {
                                        if (e_1 instanceof _Errors__WEBPACK_IMPORTED_MODULE_1__["TimeoutError"]) {
                                            // Ignore timeouts and reissue the poll.
                                            this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Poll timed out, reissuing.");
                                        }
                                        else {
                                            // Close the connection with the error as the result.
                                            this.closeError = e_1;
                                            this.running = false;
                                        }
                                    }
                                    return [3 /*break*/, 6];
                                case 6: return [3 /*break*/, 1];
                                case 7: return [3 /*break*/, 9];
                                case 8:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Polling complete.");
                                    // We will reach here with pollAborted==false when the server returned a response causing the transport to stop.
                                    // If pollAborted==true then client initiated the stop and the stop method will raise the close event after DELETE is sent.
                                    if (!this.pollAborted) {
                                        this.raiseOnClose();
                                    }
                                    return [7 /*endfinally*/];
                                case 9: return [2 /*return*/];
                            }
                        });
                    });
                };
                LongPollingTransport.prototype.send = function (data) {
                    return __awaiter(this, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            if (!this.running) {
                                return [2 /*return*/, Promise.reject(new Error("Cannot send until the transport is connected"))];
                            }
                            return [2 /*return*/, Object(_Utils__WEBPACK_IMPORTED_MODULE_4__["sendMessage"])(this.logger, "LongPolling", this.httpClient, this.url, this.accessTokenFactory, data, this.logMessageContent)];
                        });
                    });
                };
                LongPollingTransport.prototype.stop = function () {
                    return __awaiter(this, void 0, void 0, function () {
                        var deleteOptions, token;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Stopping polling.");
                                    // Tell receiving loop to stop, abort any current request, and then wait for it to finish
                                    this.running = false;
                                    this.pollAbort.abort();
                                    _a.label = 1;
                                case 1:
                                    _a.trys.push([1, , 5, 6]);
                                    return [4 /*yield*/, this.receiving];
                                case 2:
                                    _a.sent();
                                    // Send DELETE to clean up long polling on the server
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) sending DELETE request to " + this.url + ".");
                                    deleteOptions = {
                                        headers: {},
                                    };
                                    return [4 /*yield*/, this.getAccessToken()];
                                case 3:
                                    token = _a.sent();
                                    this.updateHeaderToken(deleteOptions, token);
                                    return [4 /*yield*/, this.httpClient.delete(this.url, deleteOptions)];
                                case 4:
                                    _a.sent();
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) DELETE request sent.");
                                    return [3 /*break*/, 6];
                                case 5:
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, "(LongPolling transport) Stop finished.");
                                    // Raise close event here instead of in polling
                                    // It needs to happen after the DELETE request is sent
                                    this.raiseOnClose();
                                    return [7 /*endfinally*/];
                                case 6: return [2 /*return*/];
                            }
                        });
                    });
                };
                LongPollingTransport.prototype.raiseOnClose = function () {
                    if (this.onclose) {
                        var logMessage = "(LongPolling transport) Firing onclose event.";
                        if (this.closeError) {
                            logMessage += " Error: " + this.closeError;
                        }
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Trace, logMessage);
                        this.onclose(this.closeError);
                    }
                };
                return LongPollingTransport;
            }());

            //# sourceMappingURL=LongPollingTransport.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/NodeHttpClient.js":
/*!********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/NodeHttpClient.js ***!
  \********************************************************************/
/*! exports provided: NodeHttpClient */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* WEBPACK VAR INJECTION */(function (Buffer) {/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "NodeHttpClient", function () { return NodeHttpClient; });
/* harmony import */ var _Errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Errors */ "./node_modules/@microsoft/signalr/dist/esm/Errors.js");
/* harmony import */ var _HttpClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./HttpClient */ "./node_modules/@microsoft/signalr/dist/esm/HttpClient.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
                // Copyright (c) .NET Foundation. All rights reserved.
                // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
                var __extends = (undefined && undefined.__extends) || (function () {
                    var extendStatics = Object.setPrototypeOf ||
                        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
                        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
                    return function (d, b) {
                        extendStatics(d, b);
                        function __() { this.constructor = d; }
                        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
                    };
                })();
                var __assign = (undefined && undefined.__assign) || Object.assign || function (t) {
                    for (var s, i = 1, n = arguments.length; i < n; i++) {
                        s = arguments[i];
                        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                            t[p] = s[p];
                    }
                    return t;
                };




                var requestModule;
                if (typeof XMLHttpRequest === "undefined") {
                    // In order to ignore the dynamic require in webpack builds we need to do this magic
                    // @ts-ignore: TS doesn't know about these names
                    var requireFunc = true ? require : undefined;
                    requestModule = requireFunc("request");
                }
                /** @private */
                var NodeHttpClient = /** @class */ (function (_super) {
                    __extends(NodeHttpClient, _super);
                    function NodeHttpClient(logger) {
                        var _this = _super.call(this) || this;
                        if (typeof requestModule === "undefined") {
                            throw new Error("The 'request' module could not be loaded.");
                        }
                        _this.logger = logger;
                        _this.cookieJar = requestModule.jar();
                        _this.request = requestModule.defaults({ jar: _this.cookieJar });
                        return _this;
                    }
                    NodeHttpClient.prototype.send = function (httpRequest) {
                        var _this = this;
                        return new Promise(function (resolve, reject) {
                            var requestBody;
                            if (Object(_Utils__WEBPACK_IMPORTED_MODULE_3__["isArrayBuffer"])(httpRequest.content)) {
                                requestBody = Buffer.from(httpRequest.content);
                            }
                            else {
                                requestBody = httpRequest.content || "";
                            }
                            var currentRequest = _this.request(httpRequest.url, {
                                body: requestBody,
                                // If binary is expected 'null' should be used, otherwise for text 'utf8'
                                encoding: httpRequest.responseType === "arraybuffer" ? null : "utf8",
                                headers: __assign({
                                    // Tell auth middleware to 401 instead of redirecting
                                    "X-Requested-With": "XMLHttpRequest"
                                }, httpRequest.headers),
                                method: httpRequest.method,
                                timeout: httpRequest.timeout,
                            }, function (error, response, body) {
                                if (httpRequest.abortSignal) {
                                    httpRequest.abortSignal.onabort = null;
                                }
                                if (error) {
                                    if (error.code === "ETIMEDOUT") {
                                        _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "Timeout from HTTP request.");
                                        reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["TimeoutError"]());
                                    }
                                    _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "Error from HTTP request. " + error);
                                    reject(error);
                                    return;
                                }
                                if (response.statusCode >= 200 && response.statusCode < 300) {
                                    resolve(new _HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpResponse"](response.statusCode, response.statusMessage || "", body));
                                }
                                else {
                                    reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["HttpError"](response.statusMessage || "", response.statusCode || 0));
                                }
                            });
                            if (httpRequest.abortSignal) {
                                httpRequest.abortSignal.onabort = function () {
                                    currentRequest.abort();
                                    reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["AbortError"]());
                                };
                            }
                        });
                    };
                    NodeHttpClient.prototype.getCookieString = function (url) {
                        return this.cookieJar.getCookieString(url);
                    };
                    return NodeHttpClient;
                }(_HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpClient"]));

                //# sourceMappingURL=NodeHttpClient.js.map
                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../../../../buffer/index.js */ "./node_modules/buffer/index.js").Buffer))

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/ServerSentEventsTransport.js":
/*!*******************************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/ServerSentEventsTransport.js ***!
  \*******************************************************************************/
/*! exports provided: ServerSentEventsTransport */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "ServerSentEventsTransport", function () { return ServerSentEventsTransport; });
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };



            /** @private */
            var ServerSentEventsTransport = /** @class */ (function () {
                function ServerSentEventsTransport(httpClient, accessTokenFactory, logger, logMessageContent, eventSourceConstructor) {
                    this.httpClient = httpClient;
                    this.accessTokenFactory = accessTokenFactory;
                    this.logger = logger;
                    this.logMessageContent = logMessageContent;
                    this.eventSourceConstructor = eventSourceConstructor;
                    this.onreceive = null;
                    this.onclose = null;
                }
                ServerSentEventsTransport.prototype.connect = function (url, transferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var token;
                        var _this = this;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isRequired(url, "url");
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isRequired(transferFormat, "transferFormat");
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isIn(transferFormat, _ITransport__WEBPACK_IMPORTED_MODULE_1__["TransferFormat"], "transferFormat");
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(SSE transport) Connecting.");
                                    // set url before accessTokenFactory because this.url is only for send and we set the auth header instead of the query string for send
                                    this.url = url;
                                    if (!this.accessTokenFactory) return [3 /*break*/, 2];
                                    return [4 /*yield*/, this.accessTokenFactory()];
                                case 1:
                                    token = _a.sent();
                                    if (token) {
                                        url += (url.indexOf("?") < 0 ? "?" : "&") + ("access_token=" + encodeURIComponent(token));
                                    }
                                    _a.label = 2;
                                case 2: return [2 /*return*/, new Promise(function (resolve, reject) {
                                    var opened = false;
                                    if (transferFormat !== _ITransport__WEBPACK_IMPORTED_MODULE_1__["TransferFormat"].Text) {
                                        reject(new Error("The Server-Sent Events transport only supports the 'Text' transfer format"));
                                        return;
                                    }
                                    var eventSource;
                                    if (_Utils__WEBPACK_IMPORTED_MODULE_2__["Platform"].isBrowser || _Utils__WEBPACK_IMPORTED_MODULE_2__["Platform"].isWebWorker) {
                                        eventSource = new _this.eventSourceConstructor(url, { withCredentials: true });
                                    }
                                    else {
                                        // Non-browser passes cookies via the dictionary
                                        var cookies = _this.httpClient.getCookieString(url);
                                        eventSource = new _this.eventSourceConstructor(url, { withCredentials: true, headers: { Cookie: cookies } });
                                    }
                                    try {
                                        eventSource.onmessage = function (e) {
                                            if (_this.onreceive) {
                                                try {
                                                    _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(SSE transport) data received. " + Object(_Utils__WEBPACK_IMPORTED_MODULE_2__["getDataDetail"])(e.data, _this.logMessageContent) + ".");
                                                    _this.onreceive(e.data);
                                                }
                                                catch (error) {
                                                    _this.close(error);
                                                    return;
                                                }
                                            }
                                        };
                                        eventSource.onerror = function (e) {
                                            var error = new Error(e.data || "Error occurred");
                                            if (opened) {
                                                _this.close(error);
                                            }
                                            else {
                                                reject(error);
                                            }
                                        };
                                        eventSource.onopen = function () {
                                            _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Information, "SSE connected to " + _this.url);
                                            _this.eventSource = eventSource;
                                            opened = true;
                                            resolve();
                                        };
                                    }
                                    catch (e) {
                                        reject(e);
                                        return;
                                    }
                                })];
                            }
                        });
                    });
                };
                ServerSentEventsTransport.prototype.send = function (data) {
                    return __awaiter(this, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            if (!this.eventSource) {
                                return [2 /*return*/, Promise.reject(new Error("Cannot send until the transport is connected"))];
                            }
                            return [2 /*return*/, Object(_Utils__WEBPACK_IMPORTED_MODULE_2__["sendMessage"])(this.logger, "SSE", this.httpClient, this.url, this.accessTokenFactory, data, this.logMessageContent)];
                        });
                    });
                };
                ServerSentEventsTransport.prototype.stop = function () {
                    this.close();
                    return Promise.resolve();
                };
                ServerSentEventsTransport.prototype.close = function (e) {
                    if (this.eventSource) {
                        this.eventSource.close();
                        this.eventSource = undefined;
                        if (this.onclose) {
                            this.onclose(e);
                        }
                    }
                };
                return ServerSentEventsTransport;
            }());

            //# sourceMappingURL=ServerSentEventsTransport.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/Subject.js":
/*!*************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/Subject.js ***!
  \*************************************************************/
/*! exports provided: Subject */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Subject", function () { return Subject; });
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

            /** Stream implementation to stream items to the server. */
            var Subject = /** @class */ (function () {
                function Subject() {
                    this.observers = [];
                }
                Subject.prototype.next = function (item) {
                    for (var _i = 0, _a = this.observers; _i < _a.length; _i++) {
                        var observer = _a[_i];
                        observer.next(item);
                    }
                };
                Subject.prototype.error = function (err) {
                    for (var _i = 0, _a = this.observers; _i < _a.length; _i++) {
                        var observer = _a[_i];
                        if (observer.error) {
                            observer.error(err);
                        }
                    }
                };
                Subject.prototype.complete = function () {
                    for (var _i = 0, _a = this.observers; _i < _a.length; _i++) {
                        var observer = _a[_i];
                        if (observer.complete) {
                            observer.complete();
                        }
                    }
                };
                Subject.prototype.subscribe = function (observer) {
                    this.observers.push(observer);
                    return new _Utils__WEBPACK_IMPORTED_MODULE_0__["SubjectSubscription"](this, observer);
                };
                return Subject;
            }());

            //# sourceMappingURL=Subject.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/TextMessageFormat.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/TextMessageFormat.js ***!
  \***********************************************************************/
/*! exports provided: TextMessageFormat */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "TextMessageFormat", function () { return TextMessageFormat; });
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // Not exported from index
            /** @private */
            var TextMessageFormat = /** @class */ (function () {
                function TextMessageFormat() {
                }
                TextMessageFormat.write = function (output) {
                    return "" + output + TextMessageFormat.RecordSeparator;
                };
                TextMessageFormat.parse = function (input) {
                    if (input[input.length - 1] !== TextMessageFormat.RecordSeparator) {
                        throw new Error("Message is incomplete.");
                    }
                    var messages = input.split(TextMessageFormat.RecordSeparator);
                    messages.pop();
                    return messages;
                };
                TextMessageFormat.RecordSeparatorCode = 0x1e;
                TextMessageFormat.RecordSeparator = String.fromCharCode(TextMessageFormat.RecordSeparatorCode);
                return TextMessageFormat;
            }());

            //# sourceMappingURL=TextMessageFormat.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/Utils.js":
/*!***********************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/Utils.js ***!
  \***********************************************************/
/*! exports provided: Arg, Platform, getDataDetail, formatArrayBuffer, isArrayBuffer, sendMessage, createLogger, SubjectSubscription, ConsoleLogger */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Arg", function () { return Arg; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Platform", function () { return Platform; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "getDataDetail", function () { return getDataDetail; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "formatArrayBuffer", function () { return formatArrayBuffer; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "isArrayBuffer", function () { return isArrayBuffer; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "sendMessage", function () { return sendMessage; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createLogger", function () { return createLogger; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SubjectSubscription", function () { return SubjectSubscription; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "ConsoleLogger", function () { return ConsoleLogger; });
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _Loggers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Loggers */ "./node_modules/@microsoft/signalr/dist/esm/Loggers.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };


            /** @private */
            var Arg = /** @class */ (function () {
                function Arg() {
                }
                Arg.isRequired = function (val, name) {
                    if (val === null || val === undefined) {
                        throw new Error("The '" + name + "' argument is required.");
                    }
                };
                Arg.isIn = function (val, values, name) {
                    // TypeScript enums have keys for **both** the name and the value of each enum member on the type itself.
                    if (!(val in values)) {
                        throw new Error("Unknown " + name + " value: " + val + ".");
                    }
                };
                return Arg;
            }());

            /** @private */
            var Platform = /** @class */ (function () {
                function Platform() {
                }
                Object.defineProperty(Platform, "isBrowser", {
                    get: function () {
                        return typeof window === "object";
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(Platform, "isWebWorker", {
                    get: function () {
                        return typeof self === "object" && "importScripts" in self;
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(Platform, "isNode", {
                    get: function () {
                        return !this.isBrowser && !this.isWebWorker;
                    },
                    enumerable: true,
                    configurable: true
                });
                return Platform;
            }());

            /** @private */
            function getDataDetail(data, includeContent) {
                var detail = "";
                if (isArrayBuffer(data)) {
                    detail = "Binary data of length " + data.byteLength;
                    if (includeContent) {
                        detail += ". Content: '" + formatArrayBuffer(data) + "'";
                    }
                }
                else if (typeof data === "string") {
                    detail = "String data of length " + data.length;
                    if (includeContent) {
                        detail += ". Content: '" + data + "'";
                    }
                }
                return detail;
            }
            /** @private */
            function formatArrayBuffer(data) {
                var view = new Uint8Array(data);
                // Uint8Array.map only supports returning another Uint8Array?
                var str = "";
                view.forEach(function (num) {
                    var pad = num < 16 ? "0" : "";
                    str += "0x" + pad + num.toString(16) + " ";
                });
                // Trim of trailing space.
                return str.substr(0, str.length - 1);
            }
            // Also in signalr-protocol-msgpack/Utils.ts
            /** @private */
            function isArrayBuffer(val) {
                return val && typeof ArrayBuffer !== "undefined" &&
                    (val instanceof ArrayBuffer ||
                        // Sometimes we get an ArrayBuffer that doesn't satisfy instanceof
                        (val.constructor && val.constructor.name === "ArrayBuffer"));
            }
            /** @private */
            function sendMessage(logger, transportName, httpClient, url, accessTokenFactory, content, logMessageContent) {
                return __awaiter(this, void 0, void 0, function () {
                    var _a, headers, token, responseType, response;
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0:
                                if (!accessTokenFactory) return [3 /*break*/, 2];
                                return [4 /*yield*/, accessTokenFactory()];
                            case 1:
                                token = _b.sent();
                                if (token) {
                                    headers = (_a = {},
                                        _a["Authorization"] = "Bearer " + token,
                                        _a);
                                }
                                _b.label = 2;
                            case 2:
                                logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(" + transportName + " transport) sending data. " + getDataDetail(content, logMessageContent) + ".");
                                responseType = isArrayBuffer(content) ? "arraybuffer" : "text";
                                return [4 /*yield*/, httpClient.post(url, {
                                    content: content,
                                    headers: headers,
                                    responseType: responseType,
                                })];
                            case 3:
                                response = _b.sent();
                                logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(" + transportName + " transport) request complete. Response status: " + response.statusCode + ".");
                                return [2 /*return*/];
                        }
                    });
                });
            }
            /** @private */
            function createLogger(logger) {
                if (logger === undefined) {
                    return new ConsoleLogger(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Information);
                }
                if (logger === null) {
                    return _Loggers__WEBPACK_IMPORTED_MODULE_1__["NullLogger"].instance;
                }
                if (logger.log) {
                    return logger;
                }
                return new ConsoleLogger(logger);
            }
            /** @private */
            var SubjectSubscription = /** @class */ (function () {
                function SubjectSubscription(subject, observer) {
                    this.subject = subject;
                    this.observer = observer;
                }
                SubjectSubscription.prototype.dispose = function () {
                    var index = this.subject.observers.indexOf(this.observer);
                    if (index > -1) {
                        this.subject.observers.splice(index, 1);
                    }
                    if (this.subject.observers.length === 0 && this.subject.cancelCallback) {
                        this.subject.cancelCallback().catch(function (_) { });
                    }
                };
                return SubjectSubscription;
            }());

            /** @private */
            var ConsoleLogger = /** @class */ (function () {
                function ConsoleLogger(minimumLogLevel) {
                    this.minimumLogLevel = minimumLogLevel;
                    this.outputConsole = console;
                }
                ConsoleLogger.prototype.log = function (logLevel, message) {
                    if (logLevel >= this.minimumLogLevel) {
                        switch (logLevel) {
                            case _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Critical:
                            case _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Error:
                                this.outputConsole.error("[" + new Date().toISOString() + "] " + _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"][logLevel] + ": " + message);
                                break;
                            case _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Warning:
                                this.outputConsole.warn("[" + new Date().toISOString() + "] " + _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"][logLevel] + ": " + message);
                                break;
                            case _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Information:
                                this.outputConsole.info("[" + new Date().toISOString() + "] " + _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"][logLevel] + ": " + message);
                                break;
                            default:
                                // console.debug only goes to attached debuggers in Node, so we use console.log for Trace and Debug
                                this.outputConsole.log("[" + new Date().toISOString() + "] " + _ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"][logLevel] + ": " + message);
                                break;
                        }
                    }
                };
                return ConsoleLogger;
            }());

            //# sourceMappingURL=Utils.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/WebSocketTransport.js":
/*!************************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/WebSocketTransport.js ***!
  \************************************************************************/
/*! exports provided: WebSocketTransport */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "WebSocketTransport", function () { return WebSocketTransport; });
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Utils */ "./node_modules/@microsoft/signalr/dist/esm/Utils.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
                return new (P || (P = Promise))(function (resolve, reject) {
                    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
                    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
                    function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
                    step((generator = generator.apply(thisArg, _arguments || [])).next());
                });
            };
            var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
                var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
                return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
                function verb(n) { return function (v) { return step([n, v]); }; }
                function step(op) {
                    if (f) throw new TypeError("Generator is already executing.");
                    while (_) try {
                        if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                        if (y = 0, t) op = [op[0] & 2, t.value];
                        switch (op[0]) {
                            case 0: case 1: t = op; break;
                            case 4: _.label++; return { value: op[1], done: false };
                            case 5: _.label++; y = op[1]; op = [0]; continue;
                            case 7: op = _.ops.pop(); _.trys.pop(); continue;
                            default:
                                if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                                if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                                if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                                if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                                if (t[2]) _.ops.pop();
                                _.trys.pop(); continue;
                        }
                        op = body.call(thisArg, _);
                    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
                    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
                }
            };



            /** @private */
            var WebSocketTransport = /** @class */ (function () {
                function WebSocketTransport(httpClient, accessTokenFactory, logger, logMessageContent, webSocketConstructor) {
                    this.logger = logger;
                    this.accessTokenFactory = accessTokenFactory;
                    this.logMessageContent = logMessageContent;
                    this.webSocketConstructor = webSocketConstructor;
                    this.httpClient = httpClient;
                    this.onreceive = null;
                    this.onclose = null;
                }
                WebSocketTransport.prototype.connect = function (url, transferFormat) {
                    return __awaiter(this, void 0, void 0, function () {
                        var token;
                        var _this = this;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isRequired(url, "url");
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isRequired(transferFormat, "transferFormat");
                                    _Utils__WEBPACK_IMPORTED_MODULE_2__["Arg"].isIn(transferFormat, _ITransport__WEBPACK_IMPORTED_MODULE_1__["TransferFormat"], "transferFormat");
                                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(WebSockets transport) Connecting.");
                                    if (!this.accessTokenFactory) return [3 /*break*/, 2];
                                    return [4 /*yield*/, this.accessTokenFactory()];
                                case 1:
                                    token = _a.sent();
                                    if (token) {
                                        url += (url.indexOf("?") < 0 ? "?" : "&") + ("access_token=" + encodeURIComponent(token));
                                    }
                                    _a.label = 2;
                                case 2: return [2 /*return*/, new Promise(function (resolve, reject) {
                                    url = url.replace(/^http/, "ws");
                                    var webSocket;
                                    var cookies = _this.httpClient.getCookieString(url);
                                    var opened = false;
                                    if (_Utils__WEBPACK_IMPORTED_MODULE_2__["Platform"].isNode && cookies) {
                                        // Only pass cookies when in non-browser environments
                                        webSocket = new _this.webSocketConstructor(url, undefined, {
                                            headers: {
                                                Cookie: "" + cookies,
                                            },
                                        });
                                    }
                                    if (!webSocket) {
                                        // Chrome is not happy with passing 'undefined' as protocol
                                        webSocket = new _this.webSocketConstructor(url);
                                    }
                                    if (transferFormat === _ITransport__WEBPACK_IMPORTED_MODULE_1__["TransferFormat"].Binary) {
                                        webSocket.binaryType = "arraybuffer";
                                    }
                                    // tslint:disable-next-line:variable-name
                                    webSocket.onopen = function (_event) {
                                        _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Information, "WebSocket connected to " + url + ".");
                                        _this.webSocket = webSocket;
                                        opened = true;
                                        resolve();
                                    };
                                    webSocket.onerror = function (event) {
                                        var error = null;
                                        // ErrorEvent is a browser only type we need to check if the type exists before using it
                                        if (typeof ErrorEvent !== "undefined" && event instanceof ErrorEvent) {
                                            error = event.error;
                                        }
                                        else {
                                            error = new Error("There was an error with the transport.");
                                        }
                                        reject(error);
                                    };
                                    webSocket.onmessage = function (message) {
                                        _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(WebSockets transport) data received. " + Object(_Utils__WEBPACK_IMPORTED_MODULE_2__["getDataDetail"])(message.data, _this.logMessageContent) + ".");
                                        if (_this.onreceive) {
                                            _this.onreceive(message.data);
                                        }
                                    };
                                    webSocket.onclose = function (event) {
                                        // Don't call close handler if connection was never established
                                        // We'll reject the connect call instead
                                        if (opened) {
                                            _this.close(event);
                                        }
                                        else {
                                            var error = null;
                                            // ErrorEvent is a browser only type we need to check if the type exists before using it
                                            if (typeof ErrorEvent !== "undefined" && event instanceof ErrorEvent) {
                                                error = event.error;
                                            }
                                            else {
                                                error = new Error("There was an error with the transport.");
                                            }
                                            reject(error);
                                        }
                                    };
                                })];
                            }
                        });
                    });
                };
                WebSocketTransport.prototype.send = function (data) {
                    if (this.webSocket && this.webSocket.readyState === this.webSocketConstructor.OPEN) {
                        this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(WebSockets transport) sending data. " + Object(_Utils__WEBPACK_IMPORTED_MODULE_2__["getDataDetail"])(data, this.logMessageContent) + ".");
                        this.webSocket.send(data);
                        return Promise.resolve();
                    }
                    return Promise.reject("WebSocket is not in the OPEN state");
                };
                WebSocketTransport.prototype.stop = function () {
                    if (this.webSocket) {
                        // Clear websocket handlers because we are considering the socket closed now
                        this.webSocket.onclose = function () { };
                        this.webSocket.onmessage = function () { };
                        this.webSocket.onerror = function () { };
                        this.webSocket.close();
                        this.webSocket = undefined;
                        // Manually invoke onclose callback inline so we know the HttpConnection was closed properly before returning
                        // This also solves an issue where websocket.onclose could take 18+ seconds to trigger during network disconnects
                        this.close(undefined);
                    }
                    return Promise.resolve();
                };
                WebSocketTransport.prototype.close = function (event) {
                    // webSocket will be null if the transport did not start successfully
                    this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_0__["LogLevel"].Trace, "(WebSockets transport) socket closed.");
                    if (this.onclose) {
                        if (event && (event.wasClean === false || event.code !== 1000)) {
                            this.onclose(new Error("WebSocket closed with status code: " + event.code + " (" + event.reason + ")."));
                        }
                        else {
                            this.onclose();
                        }
                    }
                };
                return WebSocketTransport;
            }());

            //# sourceMappingURL=WebSocketTransport.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/XhrHttpClient.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/XhrHttpClient.js ***!
  \*******************************************************************/
/*! exports provided: XhrHttpClient */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "XhrHttpClient", function () { return XhrHttpClient; });
/* harmony import */ var _Errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Errors */ "./node_modules/@microsoft/signalr/dist/esm/Errors.js");
/* harmony import */ var _HttpClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./HttpClient */ "./node_modules/@microsoft/signalr/dist/esm/HttpClient.js");
/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            var __extends = (undefined && undefined.__extends) || (function () {
                var extendStatics = Object.setPrototypeOf ||
                    ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
                    function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
                return function (d, b) {
                    extendStatics(d, b);
                    function __() { this.constructor = d; }
                    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
                };
            })();



            var XhrHttpClient = /** @class */ (function (_super) {
                __extends(XhrHttpClient, _super);
                function XhrHttpClient(logger) {
                    var _this = _super.call(this) || this;
                    _this.logger = logger;
                    return _this;
                }
                /** @inheritDoc */
                XhrHttpClient.prototype.send = function (request) {
                    var _this = this;
                    // Check that abort was not signaled before calling send
                    if (request.abortSignal && request.abortSignal.aborted) {
                        return Promise.reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["AbortError"]());
                    }
                    if (!request.method) {
                        return Promise.reject(new Error("No method defined."));
                    }
                    if (!request.url) {
                        return Promise.reject(new Error("No url defined."));
                    }
                    return new Promise(function (resolve, reject) {
                        var xhr = new XMLHttpRequest();
                        xhr.open(request.method, request.url, true);
                        xhr.withCredentials = true;
                        xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
                        // Explicitly setting the Content-Type header for React Native on Android platform.
                        xhr.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
                        var headers = request.headers;
                        if (headers) {
                            Object.keys(headers)
                                .forEach(function (header) {
                                    xhr.setRequestHeader(header, headers[header]);
                                });
                        }
                        if (request.responseType) {
                            xhr.responseType = request.responseType;
                        }
                        if (request.abortSignal) {
                            request.abortSignal.onabort = function () {
                                xhr.abort();
                                reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["AbortError"]());
                            };
                        }
                        if (request.timeout) {
                            xhr.timeout = request.timeout;
                        }
                        xhr.onload = function () {
                            if (request.abortSignal) {
                                request.abortSignal.onabort = null;
                            }
                            if (xhr.status >= 200 && xhr.status < 300) {
                                resolve(new _HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpResponse"](xhr.status, xhr.statusText, xhr.response || xhr.responseText));
                            }
                            else {
                                reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["HttpError"](xhr.statusText, xhr.status));
                            }
                        };
                        xhr.onerror = function () {
                            _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "Error from HTTP request. " + xhr.status + ": " + xhr.statusText + ".");
                            reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["HttpError"](xhr.statusText, xhr.status));
                        };
                        xhr.ontimeout = function () {
                            _this.logger.log(_ILogger__WEBPACK_IMPORTED_MODULE_2__["LogLevel"].Warning, "Timeout from HTTP request.");
                            reject(new _Errors__WEBPACK_IMPORTED_MODULE_0__["TimeoutError"]());
                        };
                        xhr.send(request.content || "");
                    });
                };
                return XhrHttpClient;
            }(_HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpClient"]));

            //# sourceMappingURL=XhrHttpClient.js.map

            /***/
        }),

/***/ "./node_modules/@microsoft/signalr/dist/esm/index.js":
/*!***********************************************************!*\
  !*** ./node_modules/@microsoft/signalr/dist/esm/index.js ***!
  \***********************************************************/
/*! exports provided: VERSION, AbortError, HttpError, TimeoutError, HttpClient, HttpResponse, DefaultHttpClient, HubConnection, HubConnectionState, HubConnectionBuilder, MessageType, LogLevel, HttpTransportType, TransferFormat, NullLogger, JsonHubProtocol, Subject */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "VERSION", function () { return VERSION; });
/* harmony import */ var _Errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Errors */ "./node_modules/@microsoft/signalr/dist/esm/Errors.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "AbortError", function () { return _Errors__WEBPACK_IMPORTED_MODULE_0__["AbortError"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HttpError", function () { return _Errors__WEBPACK_IMPORTED_MODULE_0__["HttpError"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "TimeoutError", function () { return _Errors__WEBPACK_IMPORTED_MODULE_0__["TimeoutError"]; });

/* harmony import */ var _HttpClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./HttpClient */ "./node_modules/@microsoft/signalr/dist/esm/HttpClient.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HttpClient", function () { return _HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpClient"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HttpResponse", function () { return _HttpClient__WEBPACK_IMPORTED_MODULE_1__["HttpResponse"]; });

/* harmony import */ var _DefaultHttpClient__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./DefaultHttpClient */ "./node_modules/@microsoft/signalr/dist/esm/DefaultHttpClient.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "DefaultHttpClient", function () { return _DefaultHttpClient__WEBPACK_IMPORTED_MODULE_2__["DefaultHttpClient"]; });

/* harmony import */ var _HubConnection__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./HubConnection */ "./node_modules/@microsoft/signalr/dist/esm/HubConnection.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HubConnection", function () { return _HubConnection__WEBPACK_IMPORTED_MODULE_3__["HubConnection"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HubConnectionState", function () { return _HubConnection__WEBPACK_IMPORTED_MODULE_3__["HubConnectionState"]; });

/* harmony import */ var _HubConnectionBuilder__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./HubConnectionBuilder */ "./node_modules/@microsoft/signalr/dist/esm/HubConnectionBuilder.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HubConnectionBuilder", function () { return _HubConnectionBuilder__WEBPACK_IMPORTED_MODULE_4__["HubConnectionBuilder"]; });

/* harmony import */ var _IHubProtocol__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./IHubProtocol */ "./node_modules/@microsoft/signalr/dist/esm/IHubProtocol.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "MessageType", function () { return _IHubProtocol__WEBPACK_IMPORTED_MODULE_5__["MessageType"]; });

/* harmony import */ var _ILogger__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./ILogger */ "./node_modules/@microsoft/signalr/dist/esm/ILogger.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "LogLevel", function () { return _ILogger__WEBPACK_IMPORTED_MODULE_6__["LogLevel"]; });

/* harmony import */ var _ITransport__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./ITransport */ "./node_modules/@microsoft/signalr/dist/esm/ITransport.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "HttpTransportType", function () { return _ITransport__WEBPACK_IMPORTED_MODULE_7__["HttpTransportType"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "TransferFormat", function () { return _ITransport__WEBPACK_IMPORTED_MODULE_7__["TransferFormat"]; });

/* harmony import */ var _Loggers__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./Loggers */ "./node_modules/@microsoft/signalr/dist/esm/Loggers.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "NullLogger", function () { return _Loggers__WEBPACK_IMPORTED_MODULE_8__["NullLogger"]; });

/* harmony import */ var _JsonHubProtocol__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./JsonHubProtocol */ "./node_modules/@microsoft/signalr/dist/esm/JsonHubProtocol.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "JsonHubProtocol", function () { return _JsonHubProtocol__WEBPACK_IMPORTED_MODULE_9__["JsonHubProtocol"]; });

/* harmony import */ var _Subject__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./Subject */ "./node_modules/@microsoft/signalr/dist/esm/Subject.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "Subject", function () { return _Subject__WEBPACK_IMPORTED_MODULE_10__["Subject"]; });

            // Copyright (c) .NET Foundation. All rights reserved.
            // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
            // Version token that will be replaced by the prepack command
            /** The version of the SignalR client. */
            var VERSION = "3.1.0";











            //# sourceMappingURL=index.js.map

            /***/
        }),

/***/ "./node_modules/base64-js/index.js":
/*!*****************************************!*\
  !*** ./node_modules/base64-js/index.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

            "use strict";


            exports.byteLength = byteLength
            exports.toByteArray = toByteArray
            exports.fromByteArray = fromByteArray

            var lookup = []
            var revLookup = []
            var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

            var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            for (var i = 0, len = code.length; i < len; ++i) {
                lookup[i] = code[i]
                revLookup[code.charCodeAt(i)] = i
            }

            // Support decoding URL-safe base64 strings, as Node.js does.
            // See: https://en.wikipedia.org/wiki/Base64#URL_applications
            revLookup['-'.charCodeAt(0)] = 62
            revLookup['_'.charCodeAt(0)] = 63

            function getLens(b64) {
                var len = b64.length

                if (len % 4 > 0) {
                    throw new Error('Invalid string. Length must be a multiple of 4')
                }

                // Trim off extra bytes after placeholder bytes are found
                // See: https://github.com/beatgammit/base64-js/issues/42
                var validLen = b64.indexOf('=')
                if (validLen === -1) validLen = len

                var placeHoldersLen = validLen === len
                    ? 0
                    : 4 - (validLen % 4)

                return [validLen, placeHoldersLen]
            }

            // base64 is 4/3 + up to two characters of the original data
            function byteLength(b64) {
                var lens = getLens(b64)
                var validLen = lens[0]
                var placeHoldersLen = lens[1]
                return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
            }

            function _byteLength(b64, validLen, placeHoldersLen) {
                return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
            }

            function toByteArray(b64) {
                var tmp
                var lens = getLens(b64)
                var validLen = lens[0]
                var placeHoldersLen = lens[1]

                var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

                var curByte = 0

                // if there are placeholders, only get up to the last complete 4 chars
                var len = placeHoldersLen > 0
                    ? validLen - 4
                    : validLen

                var i
                for (i = 0; i < len; i += 4) {
                    tmp =
                        (revLookup[b64.charCodeAt(i)] << 18) |
                        (revLookup[b64.charCodeAt(i + 1)] << 12) |
                        (revLookup[b64.charCodeAt(i + 2)] << 6) |
                        revLookup[b64.charCodeAt(i + 3)]
                    arr[curByte++] = (tmp >> 16) & 0xFF
                    arr[curByte++] = (tmp >> 8) & 0xFF
                    arr[curByte++] = tmp & 0xFF
                }

                if (placeHoldersLen === 2) {
                    tmp =
                        (revLookup[b64.charCodeAt(i)] << 2) |
                        (revLookup[b64.charCodeAt(i + 1)] >> 4)
                    arr[curByte++] = tmp & 0xFF
                }

                if (placeHoldersLen === 1) {
                    tmp =
                        (revLookup[b64.charCodeAt(i)] << 10) |
                        (revLookup[b64.charCodeAt(i + 1)] << 4) |
                        (revLookup[b64.charCodeAt(i + 2)] >> 2)
                    arr[curByte++] = (tmp >> 8) & 0xFF
                    arr[curByte++] = tmp & 0xFF
                }

                return arr
            }

            function tripletToBase64(num) {
                return lookup[num >> 18 & 0x3F] +
                    lookup[num >> 12 & 0x3F] +
                    lookup[num >> 6 & 0x3F] +
                    lookup[num & 0x3F]
            }

            function encodeChunk(uint8, start, end) {
                var tmp
                var output = []
                for (var i = start; i < end; i += 3) {
                    tmp =
                        ((uint8[i] << 16) & 0xFF0000) +
                        ((uint8[i + 1] << 8) & 0xFF00) +
                        (uint8[i + 2] & 0xFF)
                    output.push(tripletToBase64(tmp))
                }
                return output.join('')
            }

            function fromByteArray(uint8) {
                var tmp
                var len = uint8.length
                var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
                var parts = []
                var maxChunkLength = 16383 // must be multiple of 3

                // go through the array every three bytes, we'll deal with trailing stuff later
                for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
                    parts.push(encodeChunk(
                        uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
                    ))
                }

                // pad the end with zeros, but make sure to not forget the extra bytes
                if (extraBytes === 1) {
                    tmp = uint8[len - 1]
                    parts.push(
                        lookup[tmp >> 2] +
                        lookup[(tmp << 4) & 0x3F] +
                        '=='
                    )
                } else if (extraBytes === 2) {
                    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
                    parts.push(
                        lookup[tmp >> 10] +
                        lookup[(tmp >> 4) & 0x3F] +
                        lookup[(tmp << 2) & 0x3F] +
                        '='
                    )
                }

                return parts.join('')
            }


            /***/
        }),

/***/ "./node_modules/botui/build/botui.js":
/*!*******************************************!*\
  !*** ./node_modules/botui/build/botui.js ***!
  \*******************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

            var __WEBPACK_AMD_DEFINE_ARRAY__, __WEBPACK_AMD_DEFINE_RESULT__;/*
 * botui 0.3.9
 * A JS library to build the UI for your bot
 * https://botui.org
 *
 * Copyright 2019, Moin Uddin
 * Released under the MIT license.
*/

            (function (root, factory) {
                "use strict";
                if (true) {
                    !(__WEBPACK_AMD_DEFINE_ARRAY__ = [], __WEBPACK_AMD_DEFINE_RESULT__ = (function () {
                        return (root.BotUI = factory(root));
                    }).apply(exports, __WEBPACK_AMD_DEFINE_ARRAY__),
                        __WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__));
                } else { }
            }(typeof window !== 'undefined' ? window : this, function (root, undefined) {
                "use strict";

                var BotUI = (function (id, opts) {

                    opts = opts || {};

                    if (!id) {
                        throw Error('BotUI: Container id is required as first argument.');
                    }

                    if (!document.getElementById(id)) {
                        throw Error('BotUI: Element with id #' + id + ' does not exist.');
                    }

                    if (!root.Vue && !opts.vue) {
                        throw Error('BotUI: Vue is required but not found.');
                    }

                    var _botApp, // current vue instance.
                        _options = {
                            debug: false,
                            fontawesome: true,
                            searchselect: true
                        },
                        _container, // the outermost Element. Needed to scroll to bottom, for now.
                        _interface = {}, // methods returned by a BotUI() instance.
                        _actionResolve,
                        _markDownRegex = {
                            icon: /!\(([^\)]+)\)/igm, // !(icon)
                            image: /!\[(.*?)\]\((.*?)\)/igm, // ![aleternate text](src)
                            link: /\[([^\[]+)\]\(([^\)]+)\)(\^?)/igm // [text](link) ^ can be added at end to set the target as 'blank'
                        },
                        _fontAwesome = 'https://use.fontawesome.com/ea731dcb6f.js',
                        _esPromisePollyfill = 'https://cdn.jsdelivr.net/es6-promise/4.1.0/es6-promise.min.js', // mostly for IE
                        _searchselect = "https://unpkg.com/vue-select@2.4.0/dist/vue-select.js";

                    root.Vue = root.Vue || opts.vue;

                    // merge opts passed to constructor with _options
                    for (var prop in _options) {
                        if (opts.hasOwnProperty(prop)) {
                            _options[prop] = opts[prop];
                        }
                    }

                    if (!root.Promise && typeof Promise === "undefined" && !opts.promise) {
                        loadScript(_esPromisePollyfill);
                    }

                    function _linkReplacer(match, $1, $2, $3) {
                        var _target = $3 ? 'blank' : ''; // check if '^' sign is present with link syntax
                        return "<a class='botui-message-content-link' target='" + _target + "' href='" + $2 + "'>" + $1 + "</a>";
                    }

                    function _parseMarkDown(text) {
                        return text
                            .replace(_markDownRegex.image, "<img class='botui-message-content-image' src='$2' alt='$1' />")
                            .replace(_markDownRegex.icon, "<i class='botui-icon botui-message-content-icon fa fa-$1'></i>")
                            .replace(_markDownRegex.link, _linkReplacer);
                    }

                    function loadScript(src, cb) {
                        var script = document.createElement('script');
                        script.type = 'text/javascript';
                        script.src = src;

                        if (cb) {
                            script.onload = cb;
                        }

                        document.body.appendChild(script);
                    }

                    function _handleAction(text) {
                        if (_instance.action.addMessage) {
                            _interface.message.human({
                                delay: 100,
                                content: text
                            });
                        }
                        _instance.action.show = !_instance.action.autoHide;
                    }

                    var _botuiComponent = {
                        template: '<div class=\"botui botui-container\" v-botui-container><div class=\"botui-messages-container\"><div v-for=\"msg in messages\" class=\"botui-message\" :class=\"msg.cssClass\" v-botui-scroll><transition name=\"slide-fade\"><div v-if=\"msg.visible\"><div v-if=\"msg.photo && !msg.loading\" :class=\"[\'profil\', \'profile\', {human: msg.human, \'agent\': !msg.human}]\"> <img :src=\"msg.photo\" :class=\"[{human: msg.human, \'agent\': !msg.human}]\"></div><div :class=\"[{human: msg.human, \'botui-message-content\': true}, msg.type]\"><span v-if=\"msg.type == \'text\'\" v-text=\"msg.content\" v-botui-markdown></span><span v-if=\"msg.type == \'html\'\" v-html=\"msg.content\"></span> <iframe v-if=\"msg.type == \'embed\'\" :src=\"msg.content\" frameborder=\"0\" allowfullscreen></iframe></div></div></transition><div v-if=\"msg.photo && msg.loading && !msg.human\" :class=\"[\'profil\', \'profile\', {human: msg.human, \'agent\': !msg.human}]\"> <img :src=\"msg.photo\" :class=\"[{human: msg.human, \'agent\': !msg.human}]\"></div><div v-if=\"msg.loading\" class=\"botui-message-content loading\"><i class=\"dot\"></i><i class=\"dot\"></i><i class=\"dot\"></i></div></div></div><div class=\"botui-actions-container\"><transition name=\"slide-fade\"><div v-if=\"action.show\" v-botui-scroll><form v-if=\"action.type == \'text\'\" class=\"botui-actions-text\" @submit.prevent=\"handle_action_text()\" :class=\"action.cssClass\"><i v-if=\"action.text.icon\" class=\"botui-icon botui-action-text-icon fa\" :class=\"\'fa-\' + action.text.icon\"></i> <input type=\"text\" ref=\"input\" :type=\"action.text.sub_type\" v-model=\"action.text.value\" class=\"botui-actions-text-input\" :placeholder=\"action.text.placeholder\" :size=\"action.text.size\" :value=\" action.text.value\" :class=\"action.text.cssClass\" required v-focus/> <button type=\"submit\" :class=\"{\'botui-actions-buttons-button\': !!action.text.button, \'botui-actions-text-submit\': !action.text.button}\"><i v-if=\"action.text.button && action.text.button.icon\" class=\"botui-icon botui-action-button-icon fa\" :class=\"\'fa-\' + action.text.button.icon\"></i> <span>{{(action.text.button && action.text.button.label) || \'Go\'}}</span></button></form><form v-if=\"action.type == \'select\'\" class=\"botui-actions-select\" @submit.prevent=\"handle_action_select()\" :class=\"action.cssClass\"><i v-if=\"action.select.icon\" class=\"botui-icon botui-action-select-icon fa\" :class=\"\'fa-\' + action.select.icon\"></i><v-select v-if=\"action.select.searchselect && !action.select.multipleselect\" v-model=\"action.select.value\" :value=\"action.select.value\" :placeholder=\"action.select.placeholder\" class=\"botui-actions-text-searchselect\" :label=\"action.select.label\" :options=\"action.select.options\"></v-select><v-select v-else-if=\"action.select.searchselect && action.select.multipleselect\" multiple v-model=\"action.select.value\" :value=\"action.select.value\" :placeholder=\"action.select.placeholder\" class=\"botui-actions-text-searchselect\" :label=\"action.select.label\" :options=\"action.select.options\"></v-select> <select v-else v-model=\"action.select.value\" class=\"botui-actions-text-select\" :placeholder=\"action.select.placeholder\" :size=\"action.select.size\" :class=\"action.select.cssClass\" required v-focus><option v-for=\"option in action.select.options\" :class=\"action.select.optionClass\" v-bind:value=\"option.value\" :disabled=\"(option.value == \'\')?true:false\" :selected=\"(action.select.value == option.value)?\'selected\':\'\'\"> {{ option.text }}</option></select> <button type=\"submit\" :class=\"{\'botui-actions-buttons-button\': !!action.select.button, \'botui-actions-select-submit\': !action.select.button}\"><i v-if=\"action.select.button && action.select.button.icon\" class=\"botui-icon botui-action-button-icon fa\" :class=\"\'fa-\' + action.select.button.icon\"></i> <span>{{(action.select.button && action.select.button.label) || \'Ok\'}}</span></button></form><div v-if=\"action.type == \'button\'\" class=\"botui-actions-buttons\" :class=\"action.cssClass\"> <button type=\"button\" :class=\"button.cssClass\" class=\"botui-actions-buttons-button\" v-botui-scroll v-for=\"button in action.button.buttons\" @click=\"handle_action_button(button)\"><i v-if=\"button.icon\" class=\"botui-icon botui-action-button-icon fa\" :class=\"\'fa-\' + button.icon\"></i> {{button.text}}</button></div><form v-if=\"action.type == \'buttontext\'\" class=\"botui-actions-text\" @submit.prevent=\"handle_action_text()\" :class=\"action.cssClass\"><i v-if=\"action.text.icon\" class=\"botui-icon botui-action-text-icon fa\" :class=\"\'fa-\' + action.text.icon\"></i> <input type=\"text\" ref=\"input\" :type=\"action.text.sub_type\" v-model=\"action.text.value\" class=\"botui-actions-text-input\" :placeholder=\"action.text.placeholder\" :size=\"action.text.size\" :value=\"action.text.value\" :class=\"action.text.cssClass\" required v-focus/> <button type=\"submit\" :class=\"{\'botui-actions-buttons-button\': !!action.text.button, \'botui-actions-text-submit\': !action.text.button}\"><i v-if=\"action.text.button && action.text.button.icon\" class=\"botui-icon botui-action-button-icon fa\" :class=\"\'fa-\' + action.text.button.icon\"></i> <span>{{(action.text.button && action.text.button.label) || \'Go\'}}</span></button><div class=\"botui-actions-buttons\" :class=\"action.cssClass\"> <button type=\"button\" :class=\"button.cssClass\" class=\"botui-actions-buttons-button\" v-for=\"button in action.button.buttons\" @click=\"handle_action_button(button)\" autofocus><i v-if=\"button.icon\" class=\"botui-icon botui-action-button-icon fa\" :class=\"\'fa-\' + button.icon\"></i> {{button.text}}</button></div></form></div></transition></div></div>', // replaced by HTML template during build. see Gulpfile.js
                        data: function () {
                            return {
                                action: {
                                    text: {
                                        size: 30,
                                        placeholder: 'Write here ..'
                                    },
                                    button: {},
                                    show: false,
                                    type: 'text',
                                    autoHide: true,
                                    addMessage: true
                                },
                                messages: []
                            };
                        },
                        computed: {
                            isMobile: function () {
                                return root.innerWidth && root.innerWidth <= 768;
                            }
                        },
                        methods: {
                            handle_action_button: function (button) {
                                for (var i = 0; i < this.action.button.buttons.length; i++) {
                                    if (this.action.button.buttons[i].value == button.value && typeof (this.action.button.buttons[i].event) == 'function') {
                                        this.action.button.buttons[i].event(button);
                                        if (this.action.button.buttons[i].actionStop) return false;
                                        break;
                                    }
                                }

                                _handleAction(button.text);

                                var defaultActionObj = {
                                    type: 'button',
                                    text: button.text,
                                    value: button.value
                                };

                                for (var eachProperty in button) {
                                    if (button.hasOwnProperty(eachProperty)) {
                                        if (eachProperty !== 'type' && eachProperty !== 'text' && eachProperty !== 'value') {
                                            defaultActionObj[eachProperty] = button[eachProperty];
                                        }
                                    }
                                }

                                _actionResolve(defaultActionObj);
                            },
                            handle_action_text: function () {
                                if (!this.action.text.value) return;
                                _handleAction(this.action.text.value);
                                _actionResolve({
                                    type: 'text',
                                    value: this.action.text.value
                                });
                                this.action.text.value = '';
                            },
                            handle_action_select: function () {
                                if (this.action.select.searchselect && !this.action.select.multipleselect) {
                                    if (!this.action.select.value.value) return;
                                    _handleAction(this.action.select.value[this.action.select.label]);
                                    _actionResolve({
                                        type: 'text',
                                        value: this.action.select.value.value,
                                        text: this.action.select.value.text,
                                        obj: this.action.select.value
                                    });
                                }
                                if (this.action.select.searchselect && this.action.select.multipleselect) {
                                    if (!this.action.select.value) return;
                                    var values = new Array();
                                    var labels = new Array();
                                    for (var i = 0; i < this.action.select.value.length; i++) {
                                        values.push(this.action.select.value[i].value);
                                        labels.push(this.action.select.value[i][this.action.select.label]);
                                    }
                                    _handleAction(labels.join(', '));
                                    _actionResolve({
                                        type: 'text',
                                        value: values.join(', '),
                                        text: labels.join(', '),
                                        obj: this.action.select.value
                                    });
                                }
                                else {
                                    if (!this.action.select.value) return;
                                    for (var i = 0; i < this.action.select.options.length; i++) { // Find select title
                                        if (this.action.select.options[i].value == this.action.select.value) {
                                            _handleAction(this.action.select.options[i].text);
                                            _actionResolve({
                                                type: 'text',
                                                value: this.action.select.value,
                                                text: this.action.select.options[i].text
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    };

                    root.Vue.directive('botui-markdown', function (el, binding) {
                        if (binding.value == 'false') return; // v-botui-markdown="false"
                        el.innerHTML = _parseMarkDown(el.textContent);
                    });

                    root.Vue.directive('botui-scroll', {
                        inserted: function (el) {
                            _container.scrollTop = _container.scrollHeight;
                            el.scrollIntoView(true);
                        }
                    });

                    root.Vue.directive('focus', {
                        inserted: function (el) {
                            el.focus();
                        }
                    });

                    root.Vue.directive('botui-container', {
                        inserted: function (el) {
                            _container = el;
                        }
                    });

                    _botApp = new root.Vue({
                        components: {
                            'bot-ui': _botuiComponent
                        }
                    }).$mount('#' + id);

                    var _instance = _botApp.$children[0]; // to access the component's data

                    function _addMessage(_msg) {

                        if (!_msg.loading && !_msg.content) {
                            throw Error('BotUI: "content" is required in a non-loading message object.');
                        }

                        _msg.type = _msg.type || 'text';
                        _msg.visible = (_msg.delay || _msg.loading) ? false : true;
                        var _index = _instance.messages.push(_msg) - 1;

                        return new Promise(function (resolve, reject) {
                            setTimeout(function () {
                                if (_msg.delay) {
                                    _msg.visible = true;

                                    if (_msg.loading) {
                                        _msg.loading = false;
                                    }
                                }
                                resolve(_index);
                            }, _msg.delay || 0);
                        });
                    }

                    function _checkOpts(_opts) {
                        if (typeof _opts === 'string') {
                            _opts = {
                                content: _opts
                            };
                        }
                        return _opts || {};
                    }

                    _interface.message = {
                        add: function (addOpts) {
                            return _addMessage(_checkOpts(addOpts));
                        },
                        bot: function (addOpts) {
                            addOpts = _checkOpts(addOpts);
                            return _addMessage(addOpts);
                        },
                        human: function (addOpts) {
                            addOpts = _checkOpts(addOpts);
                            addOpts.human = true;
                            return _addMessage(addOpts);
                        },
                        get: function (index) {
                            return Promise.resolve(_instance.messages[index]);
                        },
                        remove: function (index) {
                            _instance.messages.splice(index, 1);
                            return Promise.resolve();
                        },
                        update: function (index, msg) { // only content can be updated, not the message type.
                            var _msg = _instance.messages[index];
                            _msg.content = msg.content;
                            _msg.visible = !msg.loading;
                            _msg.loading = !!msg.loading;
                            return Promise.resolve(msg.content);
                        },
                        removeAll: function () {
                            _instance.messages.splice(0, _instance.messages.length);
                            return Promise.resolve();
                        }
                    };

                    function mergeAtoB(objA, objB) {
                        for (var prop in objA) {
                            if (!objB.hasOwnProperty(prop)) {
                                objB[prop] = objA[prop];
                            }
                        }
                    }

                    function _checkAction(_opts) {
                        if (!_opts.action && !_opts.actionButton && !_opts.actionText) {
                            throw Error('BotUI: "action" property is required.');
                        }
                    }

                    function _showActions(_opts) {

                        _checkAction(_opts);

                        mergeAtoB({
                            type: 'text',
                            cssClass: '',
                            autoHide: true,
                            addMessage: true
                        }, _opts);

                        _instance.action.type = _opts.type;
                        _instance.action.cssClass = _opts.cssClass;
                        _instance.action.autoHide = _opts.autoHide;
                        _instance.action.addMessage = _opts.addMessage;

                        return new Promise(function (resolve, reject) {
                            _actionResolve = resolve; // resolved when action is performed, i.e: button clicked, text submitted, etc.
                            setTimeout(function () {
                                _instance.action.show = true;
                            }, _opts.delay || 0);
                        });
                    };

                    _interface.action = {
                        show: _showActions,
                        hide: function () {
                            _instance.action.show = false;
                            return Promise.resolve();
                        },
                        text: function (_opts) {
                            _checkAction(_opts);
                            _instance.action.text = _opts.action;
                            return _showActions(_opts);
                        },
                        button: function (_opts) {
                            _checkAction(_opts);
                            _opts.type = 'button';
                            _instance.action.button.buttons = _opts.action;
                            return _showActions(_opts);
                        },
                        select: function (_opts) {
                            _checkAction(_opts);
                            _opts.type = 'select';
                            _opts.action.label = _opts.action.label || 'text';
                            _opts.action.value = _opts.action.value || '';
                            _opts.action.searchselect = typeof _opts.action.searchselect !== 'undefined' ? _opts.action.searchselect : _options.searchselect;
                            _opts.action.multipleselect = _opts.action.multipleselect || false;
                            if (_opts.action.searchselect && typeof (_opts.action.value) == 'string') {
                                if (!_opts.action.multipleselect) {
                                    for (var i = 0; i < _opts.action.options.length; i++) { // Find object
                                        if (_opts.action.options[i].value == _opts.action.value) {
                                            _opts.action.value = _opts.action.options[i]
                                        }
                                    }
                                }
                                else {
                                    var vals = _opts.action.value.split(',');
                                    _opts.action.value = new Array();
                                    for (var i = 0; i < _opts.action.options.length; i++) { // Find object
                                        for (var j = 0; j < vals.length; j++) { // Search values
                                            if (_opts.action.options[i].value == vals[j]) {
                                                _opts.action.value.push(_opts.action.options[i]);
                                            }
                                        }
                                    }
                                }
                            }
                            if (!_opts.action.searchselect) { _opts.action.options.unshift({ value: '', text: _opts.action.placeholder }); }
                            _instance.action.button = _opts.action.button;
                            _instance.action.select = _opts.action;
                            return _showActions(_opts);
                        },
                        buttontext: function (_opts) {
                            _checkAction(_opts);
                            _opts.type = 'buttontext';
                            _instance.action.button.buttons = _opts.actionButton;
                            _instance.action.text = _opts.actionText;
                            return _showActions(_opts);
                        }
                    };

                    if (_options.fontawesome) {
                        loadScript(_fontAwesome);
                    }

                    if (_options.searchselect) {
                        loadScript(_searchselect, function () {
                            Vue.component('v-select', VueSelect.VueSelect);
                        });
                    }

                    if (_options.debug) {
                        _interface._botApp = _botApp; // current Vue instance
                    }

                    return _interface;
                });

                return BotUI;

            }));


            /***/
        }),

/***/ "./node_modules/buffer/index.js":
/*!**************************************!*\
  !*** ./node_modules/buffer/index.js ***!
  \**************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

            "use strict";
/* WEBPACK VAR INJECTION */(function (global) {/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <http://feross.org>
 * @license  MIT
 */
                /* eslint-disable no-proto */



                var base64 = __webpack_require__(/*! base64-js */ "./node_modules/base64-js/index.js")
                var ieee754 = __webpack_require__(/*! ieee754 */ "./node_modules/ieee754/index.js")
                var isArray = __webpack_require__(/*! isarray */ "./node_modules/isarray/index.js")

                exports.Buffer = Buffer
                exports.SlowBuffer = SlowBuffer
                exports.INSPECT_MAX_BYTES = 50

                /**
                 * If `Buffer.TYPED_ARRAY_SUPPORT`:
                 *   === true    Use Uint8Array implementation (fastest)
                 *   === false   Use Object implementation (most compatible, even IE6)
                 *
                 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
                 * Opera 11.6+, iOS 4.2+.
                 *
                 * Due to various browser bugs, sometimes the Object implementation will be used even
                 * when the browser supports typed arrays.
                 *
                 * Note:
                 *
                 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
                 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
                 *
                 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
                 *
                 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
                 *     incorrect length in some situations.
                
                 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
                 * get the Object implementation, which is slower but behaves correctly.
                 */
                Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
                    ? global.TYPED_ARRAY_SUPPORT
                    : typedArraySupport()

                /*
                 * Export kMaxLength after typed array support is determined.
                 */
                exports.kMaxLength = kMaxLength()

                function typedArraySupport() {
                    try {
                        var arr = new Uint8Array(1)
                        arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
                        return arr.foo() === 42 && // typed array instances can be augmented
                            typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
                            arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
                    } catch (e) {
                        return false
                    }
                }

                function kMaxLength() {
                    return Buffer.TYPED_ARRAY_SUPPORT
                        ? 0x7fffffff
                        : 0x3fffffff
                }

                function createBuffer(that, length) {
                    if (kMaxLength() < length) {
                        throw new RangeError('Invalid typed array length')
                    }
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        // Return an augmented `Uint8Array` instance, for best performance
                        that = new Uint8Array(length)
                        that.__proto__ = Buffer.prototype
                    } else {
                        // Fallback: Return an object instance of the Buffer class
                        if (that === null) {
                            that = new Buffer(length)
                        }
                        that.length = length
                    }

                    return that
                }

                /**
                 * The Buffer constructor returns instances of `Uint8Array` that have their
                 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
                 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
                 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
                 * returns a single octet.
                 *
                 * The `Uint8Array` prototype remains unmodified.
                 */

                function Buffer(arg, encodingOrOffset, length) {
                    if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
                        return new Buffer(arg, encodingOrOffset, length)
                    }

                    // Common case.
                    if (typeof arg === 'number') {
                        if (typeof encodingOrOffset === 'string') {
                            throw new Error(
                                'If encoding is specified then the first argument must be a string'
                            )
                        }
                        return allocUnsafe(this, arg)
                    }
                    return from(this, arg, encodingOrOffset, length)
                }

                Buffer.poolSize = 8192 // not used by this implementation

                // TODO: Legacy, not needed anymore. Remove in next major version.
                Buffer._augment = function (arr) {
                    arr.__proto__ = Buffer.prototype
                    return arr
                }

                function from(that, value, encodingOrOffset, length) {
                    if (typeof value === 'number') {
                        throw new TypeError('"value" argument must not be a number')
                    }

                    if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
                        return fromArrayBuffer(that, value, encodingOrOffset, length)
                    }

                    if (typeof value === 'string') {
                        return fromString(that, value, encodingOrOffset)
                    }

                    return fromObject(that, value)
                }

                /**
                 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
                 * if value is a number.
                 * Buffer.from(str[, encoding])
                 * Buffer.from(array)
                 * Buffer.from(buffer)
                 * Buffer.from(arrayBuffer[, byteOffset[, length]])
                 **/
                Buffer.from = function (value, encodingOrOffset, length) {
                    return from(null, value, encodingOrOffset, length)
                }

                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    Buffer.prototype.__proto__ = Uint8Array.prototype
                    Buffer.__proto__ = Uint8Array
                    if (typeof Symbol !== 'undefined' && Symbol.species &&
                        Buffer[Symbol.species] === Buffer) {
                        // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
                        Object.defineProperty(Buffer, Symbol.species, {
                            value: null,
                            configurable: true
                        })
                    }
                }

                function assertSize(size) {
                    if (typeof size !== 'number') {
                        throw new TypeError('"size" argument must be a number')
                    } else if (size < 0) {
                        throw new RangeError('"size" argument must not be negative')
                    }
                }

                function alloc(that, size, fill, encoding) {
                    assertSize(size)
                    if (size <= 0) {
                        return createBuffer(that, size)
                    }
                    if (fill !== undefined) {
                        // Only pay attention to encoding if it's a string. This
                        // prevents accidentally sending in a number that would
                        // be interpretted as a start offset.
                        return typeof encoding === 'string'
                            ? createBuffer(that, size).fill(fill, encoding)
                            : createBuffer(that, size).fill(fill)
                    }
                    return createBuffer(that, size)
                }

                /**
                 * Creates a new filled Buffer instance.
                 * alloc(size[, fill[, encoding]])
                 **/
                Buffer.alloc = function (size, fill, encoding) {
                    return alloc(null, size, fill, encoding)
                }

                function allocUnsafe(that, size) {
                    assertSize(size)
                    that = createBuffer(that, size < 0 ? 0 : checked(size) | 0)
                    if (!Buffer.TYPED_ARRAY_SUPPORT) {
                        for (var i = 0; i < size; ++i) {
                            that[i] = 0
                        }
                    }
                    return that
                }

                /**
                 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
                 * */
                Buffer.allocUnsafe = function (size) {
                    return allocUnsafe(null, size)
                }
                /**
                 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
                 */
                Buffer.allocUnsafeSlow = function (size) {
                    return allocUnsafe(null, size)
                }

                function fromString(that, string, encoding) {
                    if (typeof encoding !== 'string' || encoding === '') {
                        encoding = 'utf8'
                    }

                    if (!Buffer.isEncoding(encoding)) {
                        throw new TypeError('"encoding" must be a valid string encoding')
                    }

                    var length = byteLength(string, encoding) | 0
                    that = createBuffer(that, length)

                    var actual = that.write(string, encoding)

                    if (actual !== length) {
                        // Writing a hex string, for example, that contains invalid characters will
                        // cause everything after the first invalid character to be ignored. (e.g.
                        // 'abxxcd' will be treated as 'ab')
                        that = that.slice(0, actual)
                    }

                    return that
                }

                function fromArrayLike(that, array) {
                    var length = array.length < 0 ? 0 : checked(array.length) | 0
                    that = createBuffer(that, length)
                    for (var i = 0; i < length; i += 1) {
                        that[i] = array[i] & 255
                    }
                    return that
                }

                function fromArrayBuffer(that, array, byteOffset, length) {
                    array.byteLength // this throws if `array` is not a valid ArrayBuffer

                    if (byteOffset < 0 || array.byteLength < byteOffset) {
                        throw new RangeError('\'offset\' is out of bounds')
                    }

                    if (array.byteLength < byteOffset + (length || 0)) {
                        throw new RangeError('\'length\' is out of bounds')
                    }

                    if (byteOffset === undefined && length === undefined) {
                        array = new Uint8Array(array)
                    } else if (length === undefined) {
                        array = new Uint8Array(array, byteOffset)
                    } else {
                        array = new Uint8Array(array, byteOffset, length)
                    }

                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        // Return an augmented `Uint8Array` instance, for best performance
                        that = array
                        that.__proto__ = Buffer.prototype
                    } else {
                        // Fallback: Return an object instance of the Buffer class
                        that = fromArrayLike(that, array)
                    }
                    return that
                }

                function fromObject(that, obj) {
                    if (Buffer.isBuffer(obj)) {
                        var len = checked(obj.length) | 0
                        that = createBuffer(that, len)

                        if (that.length === 0) {
                            return that
                        }

                        obj.copy(that, 0, 0, len)
                        return that
                    }

                    if (obj) {
                        if ((typeof ArrayBuffer !== 'undefined' &&
                            obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
                            if (typeof obj.length !== 'number' || isnan(obj.length)) {
                                return createBuffer(that, 0)
                            }
                            return fromArrayLike(that, obj)
                        }

                        if (obj.type === 'Buffer' && isArray(obj.data)) {
                            return fromArrayLike(that, obj.data)
                        }
                    }

                    throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
                }

                function checked(length) {
                    // Note: cannot use `length < kMaxLength()` here because that fails when
                    // length is NaN (which is otherwise coerced to zero.)
                    if (length >= kMaxLength()) {
                        throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                            'size: 0x' + kMaxLength().toString(16) + ' bytes')
                    }
                    return length | 0
                }

                function SlowBuffer(length) {
                    if (+length != length) { // eslint-disable-line eqeqeq
                        length = 0
                    }
                    return Buffer.alloc(+length)
                }

                Buffer.isBuffer = function isBuffer(b) {
                    return !!(b != null && b._isBuffer)
                }

                Buffer.compare = function compare(a, b) {
                    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
                        throw new TypeError('Arguments must be Buffers')
                    }

                    if (a === b) return 0

                    var x = a.length
                    var y = b.length

                    for (var i = 0, len = Math.min(x, y); i < len; ++i) {
                        if (a[i] !== b[i]) {
                            x = a[i]
                            y = b[i]
                            break
                        }
                    }

                    if (x < y) return -1
                    if (y < x) return 1
                    return 0
                }

                Buffer.isEncoding = function isEncoding(encoding) {
                    switch (String(encoding).toLowerCase()) {
                        case 'hex':
                        case 'utf8':
                        case 'utf-8':
                        case 'ascii':
                        case 'latin1':
                        case 'binary':
                        case 'base64':
                        case 'ucs2':
                        case 'ucs-2':
                        case 'utf16le':
                        case 'utf-16le':
                            return true
                        default:
                            return false
                    }
                }

                Buffer.concat = function concat(list, length) {
                    if (!isArray(list)) {
                        throw new TypeError('"list" argument must be an Array of Buffers')
                    }

                    if (list.length === 0) {
                        return Buffer.alloc(0)
                    }

                    var i
                    if (length === undefined) {
                        length = 0
                        for (i = 0; i < list.length; ++i) {
                            length += list[i].length
                        }
                    }

                    var buffer = Buffer.allocUnsafe(length)
                    var pos = 0
                    for (i = 0; i < list.length; ++i) {
                        var buf = list[i]
                        if (!Buffer.isBuffer(buf)) {
                            throw new TypeError('"list" argument must be an Array of Buffers')
                        }
                        buf.copy(buffer, pos)
                        pos += buf.length
                    }
                    return buffer
                }

                function byteLength(string, encoding) {
                    if (Buffer.isBuffer(string)) {
                        return string.length
                    }
                    if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
                        (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
                        return string.byteLength
                    }
                    if (typeof string !== 'string') {
                        string = '' + string
                    }

                    var len = string.length
                    if (len === 0) return 0

                    // Use a for loop to avoid recursion
                    var loweredCase = false
                    for (; ;) {
                        switch (encoding) {
                            case 'ascii':
                            case 'latin1':
                            case 'binary':
                                return len
                            case 'utf8':
                            case 'utf-8':
                            case undefined:
                                return utf8ToBytes(string).length
                            case 'ucs2':
                            case 'ucs-2':
                            case 'utf16le':
                            case 'utf-16le':
                                return len * 2
                            case 'hex':
                                return len >>> 1
                            case 'base64':
                                return base64ToBytes(string).length
                            default:
                                if (loweredCase) return utf8ToBytes(string).length // assume utf8
                                encoding = ('' + encoding).toLowerCase()
                                loweredCase = true
                        }
                    }
                }
                Buffer.byteLength = byteLength

                function slowToString(encoding, start, end) {
                    var loweredCase = false

                    // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
                    // property of a typed array.

                    // This behaves neither like String nor Uint8Array in that we set start/end
                    // to their upper/lower bounds if the value passed is out of range.
                    // undefined is handled specially as per ECMA-262 6th Edition,
                    // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
                    if (start === undefined || start < 0) {
                        start = 0
                    }
                    // Return early if start > this.length. Done here to prevent potential uint32
                    // coercion fail below.
                    if (start > this.length) {
                        return ''
                    }

                    if (end === undefined || end > this.length) {
                        end = this.length
                    }

                    if (end <= 0) {
                        return ''
                    }

                    // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
                    end >>>= 0
                    start >>>= 0

                    if (end <= start) {
                        return ''
                    }

                    if (!encoding) encoding = 'utf8'

                    while (true) {
                        switch (encoding) {
                            case 'hex':
                                return hexSlice(this, start, end)

                            case 'utf8':
                            case 'utf-8':
                                return utf8Slice(this, start, end)

                            case 'ascii':
                                return asciiSlice(this, start, end)

                            case 'latin1':
                            case 'binary':
                                return latin1Slice(this, start, end)

                            case 'base64':
                                return base64Slice(this, start, end)

                            case 'ucs2':
                            case 'ucs-2':
                            case 'utf16le':
                            case 'utf-16le':
                                return utf16leSlice(this, start, end)

                            default:
                                if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
                                encoding = (encoding + '').toLowerCase()
                                loweredCase = true
                        }
                    }
                }

                // The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
                // Buffer instances.
                Buffer.prototype._isBuffer = true

                function swap(b, n, m) {
                    var i = b[n]
                    b[n] = b[m]
                    b[m] = i
                }

                Buffer.prototype.swap16 = function swap16() {
                    var len = this.length
                    if (len % 2 !== 0) {
                        throw new RangeError('Buffer size must be a multiple of 16-bits')
                    }
                    for (var i = 0; i < len; i += 2) {
                        swap(this, i, i + 1)
                    }
                    return this
                }

                Buffer.prototype.swap32 = function swap32() {
                    var len = this.length
                    if (len % 4 !== 0) {
                        throw new RangeError('Buffer size must be a multiple of 32-bits')
                    }
                    for (var i = 0; i < len; i += 4) {
                        swap(this, i, i + 3)
                        swap(this, i + 1, i + 2)
                    }
                    return this
                }

                Buffer.prototype.swap64 = function swap64() {
                    var len = this.length
                    if (len % 8 !== 0) {
                        throw new RangeError('Buffer size must be a multiple of 64-bits')
                    }
                    for (var i = 0; i < len; i += 8) {
                        swap(this, i, i + 7)
                        swap(this, i + 1, i + 6)
                        swap(this, i + 2, i + 5)
                        swap(this, i + 3, i + 4)
                    }
                    return this
                }

                Buffer.prototype.toString = function toString() {
                    var length = this.length | 0
                    if (length === 0) return ''
                    if (arguments.length === 0) return utf8Slice(this, 0, length)
                    return slowToString.apply(this, arguments)
                }

                Buffer.prototype.equals = function equals(b) {
                    if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
                    if (this === b) return true
                    return Buffer.compare(this, b) === 0
                }

                Buffer.prototype.inspect = function inspect() {
                    var str = ''
                    var max = exports.INSPECT_MAX_BYTES
                    if (this.length > 0) {
                        str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
                        if (this.length > max) str += ' ... '
                    }
                    return '<Buffer ' + str + '>'
                }

                Buffer.prototype.compare = function compare(target, start, end, thisStart, thisEnd) {
                    if (!Buffer.isBuffer(target)) {
                        throw new TypeError('Argument must be a Buffer')
                    }

                    if (start === undefined) {
                        start = 0
                    }
                    if (end === undefined) {
                        end = target ? target.length : 0
                    }
                    if (thisStart === undefined) {
                        thisStart = 0
                    }
                    if (thisEnd === undefined) {
                        thisEnd = this.length
                    }

                    if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
                        throw new RangeError('out of range index')
                    }

                    if (thisStart >= thisEnd && start >= end) {
                        return 0
                    }
                    if (thisStart >= thisEnd) {
                        return -1
                    }
                    if (start >= end) {
                        return 1
                    }

                    start >>>= 0
                    end >>>= 0
                    thisStart >>>= 0
                    thisEnd >>>= 0

                    if (this === target) return 0

                    var x = thisEnd - thisStart
                    var y = end - start
                    var len = Math.min(x, y)

                    var thisCopy = this.slice(thisStart, thisEnd)
                    var targetCopy = target.slice(start, end)

                    for (var i = 0; i < len; ++i) {
                        if (thisCopy[i] !== targetCopy[i]) {
                            x = thisCopy[i]
                            y = targetCopy[i]
                            break
                        }
                    }

                    if (x < y) return -1
                    if (y < x) return 1
                    return 0
                }

                // Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
                // OR the last index of `val` in `buffer` at offset <= `byteOffset`.
                //
                // Arguments:
                // - buffer - a Buffer to search
                // - val - a string, Buffer, or number
                // - byteOffset - an index into `buffer`; will be clamped to an int32
                // - encoding - an optional encoding, relevant is val is a string
                // - dir - true for indexOf, false for lastIndexOf
                function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
                    // Empty buffer means no match
                    if (buffer.length === 0) return -1

                    // Normalize byteOffset
                    if (typeof byteOffset === 'string') {
                        encoding = byteOffset
                        byteOffset = 0
                    } else if (byteOffset > 0x7fffffff) {
                        byteOffset = 0x7fffffff
                    } else if (byteOffset < -0x80000000) {
                        byteOffset = -0x80000000
                    }
                    byteOffset = +byteOffset  // Coerce to Number.
                    if (isNaN(byteOffset)) {
                        // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
                        byteOffset = dir ? 0 : (buffer.length - 1)
                    }

                    // Normalize byteOffset: negative offsets start from the end of the buffer
                    if (byteOffset < 0) byteOffset = buffer.length + byteOffset
                    if (byteOffset >= buffer.length) {
                        if (dir) return -1
                        else byteOffset = buffer.length - 1
                    } else if (byteOffset < 0) {
                        if (dir) byteOffset = 0
                        else return -1
                    }

                    // Normalize val
                    if (typeof val === 'string') {
                        val = Buffer.from(val, encoding)
                    }

                    // Finally, search either indexOf (if dir is true) or lastIndexOf
                    if (Buffer.isBuffer(val)) {
                        // Special case: looking for empty string/buffer always fails
                        if (val.length === 0) {
                            return -1
                        }
                        return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
                    } else if (typeof val === 'number') {
                        val = val & 0xFF // Search for a byte value [0-255]
                        if (Buffer.TYPED_ARRAY_SUPPORT &&
                            typeof Uint8Array.prototype.indexOf === 'function') {
                            if (dir) {
                                return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
                            } else {
                                return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
                            }
                        }
                        return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
                    }

                    throw new TypeError('val must be string, number or Buffer')
                }

                function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
                    var indexSize = 1
                    var arrLength = arr.length
                    var valLength = val.length

                    if (encoding !== undefined) {
                        encoding = String(encoding).toLowerCase()
                        if (encoding === 'ucs2' || encoding === 'ucs-2' ||
                            encoding === 'utf16le' || encoding === 'utf-16le') {
                            if (arr.length < 2 || val.length < 2) {
                                return -1
                            }
                            indexSize = 2
                            arrLength /= 2
                            valLength /= 2
                            byteOffset /= 2
                        }
                    }

                    function read(buf, i) {
                        if (indexSize === 1) {
                            return buf[i]
                        } else {
                            return buf.readUInt16BE(i * indexSize)
                        }
                    }

                    var i
                    if (dir) {
                        var foundIndex = -1
                        for (i = byteOffset; i < arrLength; i++) {
                            if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
                                if (foundIndex === -1) foundIndex = i
                                if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
                            } else {
                                if (foundIndex !== -1) i -= i - foundIndex
                                foundIndex = -1
                            }
                        }
                    } else {
                        if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
                        for (i = byteOffset; i >= 0; i--) {
                            var found = true
                            for (var j = 0; j < valLength; j++) {
                                if (read(arr, i + j) !== read(val, j)) {
                                    found = false
                                    break
                                }
                            }
                            if (found) return i
                        }
                    }

                    return -1
                }

                Buffer.prototype.includes = function includes(val, byteOffset, encoding) {
                    return this.indexOf(val, byteOffset, encoding) !== -1
                }

                Buffer.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
                    return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
                }

                Buffer.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
                    return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
                }

                function hexWrite(buf, string, offset, length) {
                    offset = Number(offset) || 0
                    var remaining = buf.length - offset
                    if (!length) {
                        length = remaining
                    } else {
                        length = Number(length)
                        if (length > remaining) {
                            length = remaining
                        }
                    }

                    // must be an even number of digits
                    var strLen = string.length
                    if (strLen % 2 !== 0) throw new TypeError('Invalid hex string')

                    if (length > strLen / 2) {
                        length = strLen / 2
                    }
                    for (var i = 0; i < length; ++i) {
                        var parsed = parseInt(string.substr(i * 2, 2), 16)
                        if (isNaN(parsed)) return i
                        buf[offset + i] = parsed
                    }
                    return i
                }

                function utf8Write(buf, string, offset, length) {
                    return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
                }

                function asciiWrite(buf, string, offset, length) {
                    return blitBuffer(asciiToBytes(string), buf, offset, length)
                }

                function latin1Write(buf, string, offset, length) {
                    return asciiWrite(buf, string, offset, length)
                }

                function base64Write(buf, string, offset, length) {
                    return blitBuffer(base64ToBytes(string), buf, offset, length)
                }

                function ucs2Write(buf, string, offset, length) {
                    return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
                }

                Buffer.prototype.write = function write(string, offset, length, encoding) {
                    // Buffer#write(string)
                    if (offset === undefined) {
                        encoding = 'utf8'
                        length = this.length
                        offset = 0
                        // Buffer#write(string, encoding)
                    } else if (length === undefined && typeof offset === 'string') {
                        encoding = offset
                        length = this.length
                        offset = 0
                        // Buffer#write(string, offset[, length][, encoding])
                    } else if (isFinite(offset)) {
                        offset = offset | 0
                        if (isFinite(length)) {
                            length = length | 0
                            if (encoding === undefined) encoding = 'utf8'
                        } else {
                            encoding = length
                            length = undefined
                        }
                        // legacy write(string, encoding, offset, length) - remove in v0.13
                    } else {
                        throw new Error(
                            'Buffer.write(string, encoding, offset[, length]) is no longer supported'
                        )
                    }

                    var remaining = this.length - offset
                    if (length === undefined || length > remaining) length = remaining

                    if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
                        throw new RangeError('Attempt to write outside buffer bounds')
                    }

                    if (!encoding) encoding = 'utf8'

                    var loweredCase = false
                    for (; ;) {
                        switch (encoding) {
                            case 'hex':
                                return hexWrite(this, string, offset, length)

                            case 'utf8':
                            case 'utf-8':
                                return utf8Write(this, string, offset, length)

                            case 'ascii':
                                return asciiWrite(this, string, offset, length)

                            case 'latin1':
                            case 'binary':
                                return latin1Write(this, string, offset, length)

                            case 'base64':
                                // Warning: maxLength not taken into account in base64Write
                                return base64Write(this, string, offset, length)

                            case 'ucs2':
                            case 'ucs-2':
                            case 'utf16le':
                            case 'utf-16le':
                                return ucs2Write(this, string, offset, length)

                            default:
                                if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
                                encoding = ('' + encoding).toLowerCase()
                                loweredCase = true
                        }
                    }
                }

                Buffer.prototype.toJSON = function toJSON() {
                    return {
                        type: 'Buffer',
                        data: Array.prototype.slice.call(this._arr || this, 0)
                    }
                }

                function base64Slice(buf, start, end) {
                    if (start === 0 && end === buf.length) {
                        return base64.fromByteArray(buf)
                    } else {
                        return base64.fromByteArray(buf.slice(start, end))
                    }
                }

                function utf8Slice(buf, start, end) {
                    end = Math.min(buf.length, end)
                    var res = []

                    var i = start
                    while (i < end) {
                        var firstByte = buf[i]
                        var codePoint = null
                        var bytesPerSequence = (firstByte > 0xEF) ? 4
                            : (firstByte > 0xDF) ? 3
                                : (firstByte > 0xBF) ? 2
                                    : 1

                        if (i + bytesPerSequence <= end) {
                            var secondByte, thirdByte, fourthByte, tempCodePoint

                            switch (bytesPerSequence) {
                                case 1:
                                    if (firstByte < 0x80) {
                                        codePoint = firstByte
                                    }
                                    break
                                case 2:
                                    secondByte = buf[i + 1]
                                    if ((secondByte & 0xC0) === 0x80) {
                                        tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
                                        if (tempCodePoint > 0x7F) {
                                            codePoint = tempCodePoint
                                        }
                                    }
                                    break
                                case 3:
                                    secondByte = buf[i + 1]
                                    thirdByte = buf[i + 2]
                                    if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
                                        tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
                                        if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
                                            codePoint = tempCodePoint
                                        }
                                    }
                                    break
                                case 4:
                                    secondByte = buf[i + 1]
                                    thirdByte = buf[i + 2]
                                    fourthByte = buf[i + 3]
                                    if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
                                        tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
                                        if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
                                            codePoint = tempCodePoint
                                        }
                                    }
                            }
                        }

                        if (codePoint === null) {
                            // we did not generate a valid codePoint so insert a
                            // replacement char (U+FFFD) and advance only 1 byte
                            codePoint = 0xFFFD
                            bytesPerSequence = 1
                        } else if (codePoint > 0xFFFF) {
                            // encode to utf16 (surrogate pair dance)
                            codePoint -= 0x10000
                            res.push(codePoint >>> 10 & 0x3FF | 0xD800)
                            codePoint = 0xDC00 | codePoint & 0x3FF
                        }

                        res.push(codePoint)
                        i += bytesPerSequence
                    }

                    return decodeCodePointsArray(res)
                }

                // Based on http://stackoverflow.com/a/22747272/680742, the browser with
                // the lowest limit is Chrome, with 0x10000 args.
                // We go 1 magnitude less, for safety
                var MAX_ARGUMENTS_LENGTH = 0x1000

                function decodeCodePointsArray(codePoints) {
                    var len = codePoints.length
                    if (len <= MAX_ARGUMENTS_LENGTH) {
                        return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
                    }

                    // Decode in chunks to avoid "call stack size exceeded".
                    var res = ''
                    var i = 0
                    while (i < len) {
                        res += String.fromCharCode.apply(
                            String,
                            codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
                        )
                    }
                    return res
                }

                function asciiSlice(buf, start, end) {
                    var ret = ''
                    end = Math.min(buf.length, end)

                    for (var i = start; i < end; ++i) {
                        ret += String.fromCharCode(buf[i] & 0x7F)
                    }
                    return ret
                }

                function latin1Slice(buf, start, end) {
                    var ret = ''
                    end = Math.min(buf.length, end)

                    for (var i = start; i < end; ++i) {
                        ret += String.fromCharCode(buf[i])
                    }
                    return ret
                }

                function hexSlice(buf, start, end) {
                    var len = buf.length

                    if (!start || start < 0) start = 0
                    if (!end || end < 0 || end > len) end = len

                    var out = ''
                    for (var i = start; i < end; ++i) {
                        out += toHex(buf[i])
                    }
                    return out
                }

                function utf16leSlice(buf, start, end) {
                    var bytes = buf.slice(start, end)
                    var res = ''
                    for (var i = 0; i < bytes.length; i += 2) {
                        res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
                    }
                    return res
                }

                Buffer.prototype.slice = function slice(start, end) {
                    var len = this.length
                    start = ~~start
                    end = end === undefined ? len : ~~end

                    if (start < 0) {
                        start += len
                        if (start < 0) start = 0
                    } else if (start > len) {
                        start = len
                    }

                    if (end < 0) {
                        end += len
                        if (end < 0) end = 0
                    } else if (end > len) {
                        end = len
                    }

                    if (end < start) end = start

                    var newBuf
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        newBuf = this.subarray(start, end)
                        newBuf.__proto__ = Buffer.prototype
                    } else {
                        var sliceLen = end - start
                        newBuf = new Buffer(sliceLen, undefined)
                        for (var i = 0; i < sliceLen; ++i) {
                            newBuf[i] = this[i + start]
                        }
                    }

                    return newBuf
                }

                /*
                 * Need to make sure that buffer isn't trying to write out of bounds.
                 */
                function checkOffset(offset, ext, length) {
                    if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
                    if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
                }

                Buffer.prototype.readUIntLE = function readUIntLE(offset, byteLength, noAssert) {
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) checkOffset(offset, byteLength, this.length)

                    var val = this[offset]
                    var mul = 1
                    var i = 0
                    while (++i < byteLength && (mul *= 0x100)) {
                        val += this[offset + i] * mul
                    }

                    return val
                }

                Buffer.prototype.readUIntBE = function readUIntBE(offset, byteLength, noAssert) {
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) {
                        checkOffset(offset, byteLength, this.length)
                    }

                    var val = this[offset + --byteLength]
                    var mul = 1
                    while (byteLength > 0 && (mul *= 0x100)) {
                        val += this[offset + --byteLength] * mul
                    }

                    return val
                }

                Buffer.prototype.readUInt8 = function readUInt8(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 1, this.length)
                    return this[offset]
                }

                Buffer.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 2, this.length)
                    return this[offset] | (this[offset + 1] << 8)
                }

                Buffer.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 2, this.length)
                    return (this[offset] << 8) | this[offset + 1]
                }

                Buffer.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)

                    return ((this[offset]) |
                        (this[offset + 1] << 8) |
                        (this[offset + 2] << 16)) +
                        (this[offset + 3] * 0x1000000)
                }

                Buffer.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)

                    return (this[offset] * 0x1000000) +
                        ((this[offset + 1] << 16) |
                            (this[offset + 2] << 8) |
                            this[offset + 3])
                }

                Buffer.prototype.readIntLE = function readIntLE(offset, byteLength, noAssert) {
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) checkOffset(offset, byteLength, this.length)

                    var val = this[offset]
                    var mul = 1
                    var i = 0
                    while (++i < byteLength && (mul *= 0x100)) {
                        val += this[offset + i] * mul
                    }
                    mul *= 0x80

                    if (val >= mul) val -= Math.pow(2, 8 * byteLength)

                    return val
                }

                Buffer.prototype.readIntBE = function readIntBE(offset, byteLength, noAssert) {
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) checkOffset(offset, byteLength, this.length)

                    var i = byteLength
                    var mul = 1
                    var val = this[offset + --i]
                    while (i > 0 && (mul *= 0x100)) {
                        val += this[offset + --i] * mul
                    }
                    mul *= 0x80

                    if (val >= mul) val -= Math.pow(2, 8 * byteLength)

                    return val
                }

                Buffer.prototype.readInt8 = function readInt8(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 1, this.length)
                    if (!(this[offset] & 0x80)) return (this[offset])
                    return ((0xff - this[offset] + 1) * -1)
                }

                Buffer.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 2, this.length)
                    var val = this[offset] | (this[offset + 1] << 8)
                    return (val & 0x8000) ? val | 0xFFFF0000 : val
                }

                Buffer.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 2, this.length)
                    var val = this[offset + 1] | (this[offset] << 8)
                    return (val & 0x8000) ? val | 0xFFFF0000 : val
                }

                Buffer.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)

                    return (this[offset]) |
                        (this[offset + 1] << 8) |
                        (this[offset + 2] << 16) |
                        (this[offset + 3] << 24)
                }

                Buffer.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)

                    return (this[offset] << 24) |
                        (this[offset + 1] << 16) |
                        (this[offset + 2] << 8) |
                        (this[offset + 3])
                }

                Buffer.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)
                    return ieee754.read(this, offset, true, 23, 4)
                }

                Buffer.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 4, this.length)
                    return ieee754.read(this, offset, false, 23, 4)
                }

                Buffer.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 8, this.length)
                    return ieee754.read(this, offset, true, 52, 8)
                }

                Buffer.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
                    if (!noAssert) checkOffset(offset, 8, this.length)
                    return ieee754.read(this, offset, false, 52, 8)
                }

                function checkInt(buf, value, offset, ext, max, min) {
                    if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
                    if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
                    if (offset + ext > buf.length) throw new RangeError('Index out of range')
                }

                Buffer.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength, noAssert) {
                    value = +value
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) {
                        var maxBytes = Math.pow(2, 8 * byteLength) - 1
                        checkInt(this, value, offset, byteLength, maxBytes, 0)
                    }

                    var mul = 1
                    var i = 0
                    this[offset] = value & 0xFF
                    while (++i < byteLength && (mul *= 0x100)) {
                        this[offset + i] = (value / mul) & 0xFF
                    }

                    return offset + byteLength
                }

                Buffer.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength, noAssert) {
                    value = +value
                    offset = offset | 0
                    byteLength = byteLength | 0
                    if (!noAssert) {
                        var maxBytes = Math.pow(2, 8 * byteLength) - 1
                        checkInt(this, value, offset, byteLength, maxBytes, 0)
                    }

                    var i = byteLength - 1
                    var mul = 1
                    this[offset + i] = value & 0xFF
                    while (--i >= 0 && (mul *= 0x100)) {
                        this[offset + i] = (value / mul) & 0xFF
                    }

                    return offset + byteLength
                }

                Buffer.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
                    if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
                    this[offset] = (value & 0xff)
                    return offset + 1
                }

                function objectWriteUInt16(buf, value, offset, littleEndian) {
                    if (value < 0) value = 0xffff + value + 1
                    for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
                        buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
                            (littleEndian ? i : 1 - i) * 8
                    }
                }

                Buffer.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value & 0xff)
                        this[offset + 1] = (value >>> 8)
                    } else {
                        objectWriteUInt16(this, value, offset, true)
                    }
                    return offset + 2
                }

                Buffer.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value >>> 8)
                        this[offset + 1] = (value & 0xff)
                    } else {
                        objectWriteUInt16(this, value, offset, false)
                    }
                    return offset + 2
                }

                function objectWriteUInt32(buf, value, offset, littleEndian) {
                    if (value < 0) value = 0xffffffff + value + 1
                    for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
                        buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
                    }
                }

                Buffer.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset + 3] = (value >>> 24)
                        this[offset + 2] = (value >>> 16)
                        this[offset + 1] = (value >>> 8)
                        this[offset] = (value & 0xff)
                    } else {
                        objectWriteUInt32(this, value, offset, true)
                    }
                    return offset + 4
                }

                Buffer.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value >>> 24)
                        this[offset + 1] = (value >>> 16)
                        this[offset + 2] = (value >>> 8)
                        this[offset + 3] = (value & 0xff)
                    } else {
                        objectWriteUInt32(this, value, offset, false)
                    }
                    return offset + 4
                }

                Buffer.prototype.writeIntLE = function writeIntLE(value, offset, byteLength, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) {
                        var limit = Math.pow(2, 8 * byteLength - 1)

                        checkInt(this, value, offset, byteLength, limit - 1, -limit)
                    }

                    var i = 0
                    var mul = 1
                    var sub = 0
                    this[offset] = value & 0xFF
                    while (++i < byteLength && (mul *= 0x100)) {
                        if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
                            sub = 1
                        }
                        this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
                    }

                    return offset + byteLength
                }

                Buffer.prototype.writeIntBE = function writeIntBE(value, offset, byteLength, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) {
                        var limit = Math.pow(2, 8 * byteLength - 1)

                        checkInt(this, value, offset, byteLength, limit - 1, -limit)
                    }

                    var i = byteLength - 1
                    var mul = 1
                    var sub = 0
                    this[offset + i] = value & 0xFF
                    while (--i >= 0 && (mul *= 0x100)) {
                        if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
                            sub = 1
                        }
                        this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
                    }

                    return offset + byteLength
                }

                Buffer.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
                    if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
                    if (value < 0) value = 0xff + value + 1
                    this[offset] = (value & 0xff)
                    return offset + 1
                }

                Buffer.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value & 0xff)
                        this[offset + 1] = (value >>> 8)
                    } else {
                        objectWriteUInt16(this, value, offset, true)
                    }
                    return offset + 2
                }

                Buffer.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value >>> 8)
                        this[offset + 1] = (value & 0xff)
                    } else {
                        objectWriteUInt16(this, value, offset, false)
                    }
                    return offset + 2
                }

                Buffer.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value & 0xff)
                        this[offset + 1] = (value >>> 8)
                        this[offset + 2] = (value >>> 16)
                        this[offset + 3] = (value >>> 24)
                    } else {
                        objectWriteUInt32(this, value, offset, true)
                    }
                    return offset + 4
                }

                Buffer.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
                    value = +value
                    offset = offset | 0
                    if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
                    if (value < 0) value = 0xffffffff + value + 1
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        this[offset] = (value >>> 24)
                        this[offset + 1] = (value >>> 16)
                        this[offset + 2] = (value >>> 8)
                        this[offset + 3] = (value & 0xff)
                    } else {
                        objectWriteUInt32(this, value, offset, false)
                    }
                    return offset + 4
                }

                function checkIEEE754(buf, value, offset, ext, max, min) {
                    if (offset + ext > buf.length) throw new RangeError('Index out of range')
                    if (offset < 0) throw new RangeError('Index out of range')
                }

                function writeFloat(buf, value, offset, littleEndian, noAssert) {
                    if (!noAssert) {
                        checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
                    }
                    ieee754.write(buf, value, offset, littleEndian, 23, 4)
                    return offset + 4
                }

                Buffer.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
                    return writeFloat(this, value, offset, true, noAssert)
                }

                Buffer.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
                    return writeFloat(this, value, offset, false, noAssert)
                }

                function writeDouble(buf, value, offset, littleEndian, noAssert) {
                    if (!noAssert) {
                        checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
                    }
                    ieee754.write(buf, value, offset, littleEndian, 52, 8)
                    return offset + 8
                }

                Buffer.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
                    return writeDouble(this, value, offset, true, noAssert)
                }

                Buffer.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
                    return writeDouble(this, value, offset, false, noAssert)
                }

                // copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
                Buffer.prototype.copy = function copy(target, targetStart, start, end) {
                    if (!start) start = 0
                    if (!end && end !== 0) end = this.length
                    if (targetStart >= target.length) targetStart = target.length
                    if (!targetStart) targetStart = 0
                    if (end > 0 && end < start) end = start

                    // Copy 0 bytes; we're done
                    if (end === start) return 0
                    if (target.length === 0 || this.length === 0) return 0

                    // Fatal error conditions
                    if (targetStart < 0) {
                        throw new RangeError('targetStart out of bounds')
                    }
                    if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
                    if (end < 0) throw new RangeError('sourceEnd out of bounds')

                    // Are we oob?
                    if (end > this.length) end = this.length
                    if (target.length - targetStart < end - start) {
                        end = target.length - targetStart + start
                    }

                    var len = end - start
                    var i

                    if (this === target && start < targetStart && targetStart < end) {
                        // descending copy from end
                        for (i = len - 1; i >= 0; --i) {
                            target[i + targetStart] = this[i + start]
                        }
                    } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
                        // ascending copy from start
                        for (i = 0; i < len; ++i) {
                            target[i + targetStart] = this[i + start]
                        }
                    } else {
                        Uint8Array.prototype.set.call(
                            target,
                            this.subarray(start, start + len),
                            targetStart
                        )
                    }

                    return len
                }

                // Usage:
                //    buffer.fill(number[, offset[, end]])
                //    buffer.fill(buffer[, offset[, end]])
                //    buffer.fill(string[, offset[, end]][, encoding])
                Buffer.prototype.fill = function fill(val, start, end, encoding) {
                    // Handle string cases:
                    if (typeof val === 'string') {
                        if (typeof start === 'string') {
                            encoding = start
                            start = 0
                            end = this.length
                        } else if (typeof end === 'string') {
                            encoding = end
                            end = this.length
                        }
                        if (val.length === 1) {
                            var code = val.charCodeAt(0)
                            if (code < 256) {
                                val = code
                            }
                        }
                        if (encoding !== undefined && typeof encoding !== 'string') {
                            throw new TypeError('encoding must be a string')
                        }
                        if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
                            throw new TypeError('Unknown encoding: ' + encoding)
                        }
                    } else if (typeof val === 'number') {
                        val = val & 255
                    }

                    // Invalid ranges are not set to a default, so can range check early.
                    if (start < 0 || this.length < start || this.length < end) {
                        throw new RangeError('Out of range index')
                    }

                    if (end <= start) {
                        return this
                    }

                    start = start >>> 0
                    end = end === undefined ? this.length : end >>> 0

                    if (!val) val = 0

                    var i
                    if (typeof val === 'number') {
                        for (i = start; i < end; ++i) {
                            this[i] = val
                        }
                    } else {
                        var bytes = Buffer.isBuffer(val)
                            ? val
                            : utf8ToBytes(new Buffer(val, encoding).toString())
                        var len = bytes.length
                        for (i = 0; i < end - start; ++i) {
                            this[i + start] = bytes[i % len]
                        }
                    }

                    return this
                }

                // HELPER FUNCTIONS
                // ================

                var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

                function base64clean(str) {
                    // Node strips out invalid characters like \n and \t from the string, base64-js does not
                    str = stringtrim(str).replace(INVALID_BASE64_RE, '')
                    // Node converts strings with length < 2 to ''
                    if (str.length < 2) return ''
                    // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
                    while (str.length % 4 !== 0) {
                        str = str + '='
                    }
                    return str
                }

                function stringtrim(str) {
                    if (str.trim) return str.trim()
                    return str.replace(/^\s+|\s+$/g, '')
                }

                function toHex(n) {
                    if (n < 16) return '0' + n.toString(16)
                    return n.toString(16)
                }

                function utf8ToBytes(string, units) {
                    units = units || Infinity
                    var codePoint
                    var length = string.length
                    var leadSurrogate = null
                    var bytes = []

                    for (var i = 0; i < length; ++i) {
                        codePoint = string.charCodeAt(i)

                        // is surrogate component
                        if (codePoint > 0xD7FF && codePoint < 0xE000) {
                            // last char was a lead
                            if (!leadSurrogate) {
                                // no lead yet
                                if (codePoint > 0xDBFF) {
                                    // unexpected trail
                                    if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
                                    continue
                                } else if (i + 1 === length) {
                                    // unpaired lead
                                    if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
                                    continue
                                }

                                // valid lead
                                leadSurrogate = codePoint

                                continue
                            }

                            // 2 leads in a row
                            if (codePoint < 0xDC00) {
                                if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
                                leadSurrogate = codePoint
                                continue
                            }

                            // valid surrogate pair
                            codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
                        } else if (leadSurrogate) {
                            // valid bmp char, but last char was a lead
                            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
                        }

                        leadSurrogate = null

                        // encode utf8
                        if (codePoint < 0x80) {
                            if ((units -= 1) < 0) break
                            bytes.push(codePoint)
                        } else if (codePoint < 0x800) {
                            if ((units -= 2) < 0) break
                            bytes.push(
                                codePoint >> 0x6 | 0xC0,
                                codePoint & 0x3F | 0x80
                            )
                        } else if (codePoint < 0x10000) {
                            if ((units -= 3) < 0) break
                            bytes.push(
                                codePoint >> 0xC | 0xE0,
                                codePoint >> 0x6 & 0x3F | 0x80,
                                codePoint & 0x3F | 0x80
                            )
                        } else if (codePoint < 0x110000) {
                            if ((units -= 4) < 0) break
                            bytes.push(
                                codePoint >> 0x12 | 0xF0,
                                codePoint >> 0xC & 0x3F | 0x80,
                                codePoint >> 0x6 & 0x3F | 0x80,
                                codePoint & 0x3F | 0x80
                            )
                        } else {
                            throw new Error('Invalid code point')
                        }
                    }

                    return bytes
                }

                function asciiToBytes(str) {
                    var byteArray = []
                    for (var i = 0; i < str.length; ++i) {
                        // Node's code seems to be doing this and not & 0x7F..
                        byteArray.push(str.charCodeAt(i) & 0xFF)
                    }
                    return byteArray
                }

                function utf16leToBytes(str, units) {
                    var c, hi, lo
                    var byteArray = []
                    for (var i = 0; i < str.length; ++i) {
                        if ((units -= 2) < 0) break

                        c = str.charCodeAt(i)
                        hi = c >> 8
                        lo = c % 256
                        byteArray.push(lo)
                        byteArray.push(hi)
                    }

                    return byteArray
                }

                function base64ToBytes(str) {
                    return base64.toByteArray(base64clean(str))
                }

                function blitBuffer(src, dst, offset, length) {
                    for (var i = 0; i < length; ++i) {
                        if ((i + offset >= dst.length) || (i >= src.length)) break
                        dst[i + offset] = src[i]
                    }
                    return i
                }

                function isnan(val) {
                    return val !== val // eslint-disable-line no-self-compare
                }

                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js")))

            /***/
        }),

/***/ "./node_modules/css-vendor/dist/css-vendor.esm.js":
/*!********************************************************!*\
  !*** ./node_modules/css-vendor/dist/css-vendor.esm.js ***!
  \********************************************************/
/*! exports provided: prefix, supportedKeyframes, supportedProperty, supportedValue */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "prefix", function () { return prefix; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "supportedKeyframes", function () { return supportedKeyframes; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "supportedProperty", function () { return supportedProperty; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "supportedValue", function () { return supportedValue; });
/* harmony import */ var is_in_browser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! is-in-browser */ "./node_modules/is-in-browser/dist/module.js");
/* harmony import */ var _babel_runtime_helpers_esm_toConsumableArray__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @babel/runtime/helpers/esm/toConsumableArray */ "./node_modules/@babel/runtime/helpers/esm/toConsumableArray.js");



            // Export javascript style and css style vendor prefixes.
            var js = '';
            var css = '';
            var vendor = '';
            var browser = '';
            var isTouch = is_in_browser__WEBPACK_IMPORTED_MODULE_0__["default"] && 'ontouchstart' in document.documentElement; // We should not do anything if required serverside.

            if (is_in_browser__WEBPACK_IMPORTED_MODULE_0__["default"]) {
                // Order matters. We need to check Webkit the last one because
                // other vendors use to add Webkit prefixes to some properties
                var jsCssMap = {
                    Moz: '-moz-',
                    ms: '-ms-',
                    O: '-o-',
                    Webkit: '-webkit-'
                };

                var _document$createEleme = document.createElement('p'),
                    style = _document$createEleme.style;

                var testProp = 'Transform';

                for (var key in jsCssMap) {
                    if (key + testProp in style) {
                        js = key;
                        css = jsCssMap[key];
                        break;
                    }
                } // Correctly detect the Edge browser.


                if (js === 'Webkit' && 'msHyphens' in style) {
                    js = 'ms';
                    css = jsCssMap.ms;
                    browser = 'edge';
                } // Correctly detect the Safari browser.


                if (js === 'Webkit' && '-apple-trailing-word' in style) {
                    vendor = 'apple';
                }
            }
            /**
             * Vendor prefix string for the current browser.
             *
             * @type {{js: String, css: String, vendor: String, browser: String}}
             * @api public
             */


            var prefix = {
                js: js,
                css: css,
                vendor: vendor,
                browser: browser,
                isTouch: isTouch
            };

            /**
             * Test if a keyframe at-rule should be prefixed or not
             *
             * @param {String} vendor prefix string for the current browser.
             * @return {String}
             * @api public
             */

            function supportedKeyframes(key) {
                // Keyframes is already prefixed. e.g. key = '@-webkit-keyframes a'
                if (key[1] === '-') return key; // No need to prefix IE/Edge. Older browsers will ignore unsupported rules.
                // https://caniuse.com/#search=keyframes

                if (prefix.js === 'ms') return key;
                return "@" + prefix.css + "keyframes" + key.substr(10);
            }

            // https://caniuse.com/#search=appearance

            var appearence = {
                noPrefill: ['appearance'],
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'appearance') return false;
                    if (prefix.js === 'ms') return "-webkit-" + prop;
                    return prefix.css + prop;
                }
            };

            // https://caniuse.com/#search=color-adjust

            var colorAdjust = {
                noPrefill: ['color-adjust'],
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'color-adjust') return false;
                    if (prefix.js === 'Webkit') return prefix.css + "print-" + prop;
                    return prop;
                }
            };

            var regExp = /[-\s]+(.)?/g;
            /**
             * Replaces the letter with the capital letter
             *
             * @param {String} match
             * @param {String} c
             * @return {String}
             * @api private
             */

            function toUpper(match, c) {
                return c ? c.toUpperCase() : '';
            }
            /**
             * Convert dash separated strings to camel-cased.
             *
             * @param {String} str
             * @return {String}
             * @api private
             */


            function camelize(str) {
                return str.replace(regExp, toUpper);
            }

            /**
             * Convert dash separated strings to pascal cased.
             *
             * @param {String} str
             * @return {String}
             * @api private
             */

            function pascalize(str) {
                return camelize("-" + str);
            }

            // but we can use a longhand property instead.
            // https://caniuse.com/#search=mask

            var mask = {
                noPrefill: ['mask'],
                supportedProperty: function supportedProperty(prop, style) {
                    if (!/^mask/.test(prop)) return false;

                    if (prefix.js === 'Webkit') {
                        var longhand = 'mask-image';

                        if (camelize(longhand) in style) {
                            return prop;
                        }

                        if (prefix.js + pascalize(longhand) in style) {
                            return prefix.css + prop;
                        }
                    }

                    return prop;
                }
            };

            // https://caniuse.com/#search=text-orientation

            var textOrientation = {
                noPrefill: ['text-orientation'],
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'text-orientation') return false;

                    if (prefix.vendor === 'apple' && !prefix.isTouch) {
                        return prefix.css + prop;
                    }

                    return prop;
                }
            };

            // https://caniuse.com/#search=transform

            var transform = {
                noPrefill: ['transform'],
                supportedProperty: function supportedProperty(prop, style, options) {
                    if (prop !== 'transform') return false;

                    if (options.transform) {
                        return prop;
                    }

                    return prefix.css + prop;
                }
            };

            // https://caniuse.com/#search=transition

            var transition = {
                noPrefill: ['transition'],
                supportedProperty: function supportedProperty(prop, style, options) {
                    if (prop !== 'transition') return false;

                    if (options.transition) {
                        return prop;
                    }

                    return prefix.css + prop;
                }
            };

            // https://caniuse.com/#search=writing-mode

            var writingMode = {
                noPrefill: ['writing-mode'],
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'writing-mode') return false;

                    if (prefix.js === 'Webkit' || prefix.js === 'ms') {
                        return prefix.css + prop;
                    }

                    return prop;
                }
            };

            // https://caniuse.com/#search=user-select

            var userSelect = {
                noPrefill: ['user-select'],
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'user-select') return false;

                    if (prefix.js === 'Moz' || prefix.js === 'ms' || prefix.vendor === 'apple') {
                        return prefix.css + prop;
                    }

                    return prop;
                }
            };

            // https://caniuse.com/#search=multicolumn
            // https://github.com/postcss/autoprefixer/issues/491
            // https://github.com/postcss/autoprefixer/issues/177

            var breakPropsOld = {
                supportedProperty: function supportedProperty(prop, style) {
                    if (!/^break-/.test(prop)) return false;

                    if (prefix.js === 'Webkit') {
                        var jsProp = "WebkitColumn" + pascalize(prop);
                        return jsProp in style ? prefix.css + "column-" + prop : false;
                    }

                    if (prefix.js === 'Moz') {
                        var _jsProp = "page" + pascalize(prop);

                        return _jsProp in style ? "page-" + prop : false;
                    }

                    return false;
                }
            };

            // See https://github.com/postcss/autoprefixer/issues/324.

            var inlineLogicalOld = {
                supportedProperty: function supportedProperty(prop, style) {
                    if (!/^(border|margin|padding)-inline/.test(prop)) return false;
                    if (prefix.js === 'Moz') return prop;
                    var newProp = prop.replace('-inline', '');
                    return prefix.js + pascalize(newProp) in style ? prefix.css + newProp : false;
                }
            };

            // Camelization is required because we can't test using.
            // CSS syntax for e.g. in FF.

            var unprefixed = {
                supportedProperty: function supportedProperty(prop, style) {
                    return camelize(prop) in style ? prop : false;
                }
            };

            var prefixed = {
                supportedProperty: function supportedProperty(prop, style) {
                    var pascalized = pascalize(prop); // Return custom CSS variable without prefixing.

                    if (prop[0] === '-') return prop; // Return already prefixed value without prefixing.

                    if (prop[0] === '-' && prop[1] === '-') return prop;
                    if (prefix.js + pascalized in style) return prefix.css + prop; // Try webkit fallback.

                    if (prefix.js !== 'Webkit' && "Webkit" + pascalized in style) return "-webkit-" + prop;
                    return false;
                }
            };

            // https://caniuse.com/#search=scroll-snap

            var scrollSnap = {
                supportedProperty: function supportedProperty(prop) {
                    if (prop.substring(0, 11) !== 'scroll-snap') return false;

                    if (prefix.js === 'ms') {
                        return "" + prefix.css + prop;
                    }

                    return prop;
                }
            };

            // https://caniuse.com/#search=overscroll-behavior

            var overscrollBehavior = {
                supportedProperty: function supportedProperty(prop) {
                    if (prop !== 'overscroll-behavior') return false;

                    if (prefix.js === 'ms') {
                        return prefix.css + "scroll-chaining";
                    }

                    return prop;
                }
            };

            var propMap = {
                'flex-grow': 'flex-positive',
                'flex-shrink': 'flex-negative',
                'flex-basis': 'flex-preferred-size',
                'justify-content': 'flex-pack',
                order: 'flex-order',
                'align-items': 'flex-align',
                'align-content': 'flex-line-pack' // 'align-self' is handled by 'align-self' plugin.

            }; // Support old flex spec from 2012.

            var flex2012 = {
                supportedProperty: function supportedProperty(prop, style) {
                    var newProp = propMap[prop];
                    if (!newProp) return false;
                    return prefix.js + pascalize(newProp) in style ? prefix.css + newProp : false;
                }
            };

            var propMap$1 = {
                flex: 'box-flex',
                'flex-grow': 'box-flex',
                'flex-direction': ['box-orient', 'box-direction'],
                order: 'box-ordinal-group',
                'align-items': 'box-align',
                'flex-flow': ['box-orient', 'box-direction'],
                'justify-content': 'box-pack'
            };
            var propKeys = Object.keys(propMap$1);

            var prefixCss = function prefixCss(p) {
                return prefix.css + p;
            }; // Support old flex spec from 2009.


            var flex2009 = {
                supportedProperty: function supportedProperty(prop, style, _ref) {
                    var multiple = _ref.multiple;

                    if (propKeys.indexOf(prop) > -1) {
                        var newProp = propMap$1[prop];

                        if (!Array.isArray(newProp)) {
                            return prefix.js + pascalize(newProp) in style ? prefix.css + newProp : false;
                        }

                        if (!multiple) return false;

                        for (var i = 0; i < newProp.length; i++) {
                            if (!(prefix.js + pascalize(newProp[0]) in style)) {
                                return false;
                            }
                        }

                        return newProp.map(prefixCss);
                    }

                    return false;
                }
            };

            // plugins = [
            //   ...plugins,
            //    breakPropsOld,
            //    inlineLogicalOld,
            //    unprefixed,
            //    prefixed,
            //    scrollSnap,
            //    flex2012,
            //    flex2009
            // ]
            // Plugins without 'noPrefill' value, going last.
            // 'flex-*' plugins should be at the bottom.
            // 'flex2009' going after 'flex2012'.
            // 'prefixed' going after 'unprefixed'

            var plugins = [appearence, colorAdjust, mask, textOrientation, transform, transition, writingMode, userSelect, breakPropsOld, inlineLogicalOld, unprefixed, prefixed, scrollSnap, overscrollBehavior, flex2012, flex2009];
            var propertyDetectors = plugins.filter(function (p) {
                return p.supportedProperty;
            }).map(function (p) {
                return p.supportedProperty;
            });
            var noPrefill = plugins.filter(function (p) {
                return p.noPrefill;
            }).reduce(function (a, p) {
                a.push.apply(a, Object(_babel_runtime_helpers_esm_toConsumableArray__WEBPACK_IMPORTED_MODULE_1__["default"])(p.noPrefill));
                return a;
            }, []);

            var el;
            var cache = {};

            if (is_in_browser__WEBPACK_IMPORTED_MODULE_0__["default"]) {
                el = document.createElement('p'); // We test every property on vendor prefix requirement.
                // Once tested, result is cached. It gives us up to 70% perf boost.
                // http://jsperf.com/element-style-object-access-vs-plain-object
                //
                // Prefill cache with known css properties to reduce amount of
                // properties we need to feature test at runtime.
                // http://davidwalsh.name/vendor-prefix

                var computed = window.getComputedStyle(document.documentElement, '');

                for (var key$1 in computed) {
                    // eslint-disable-next-line no-restricted-globals
                    if (!isNaN(key$1)) cache[computed[key$1]] = computed[key$1];
                } // Properties that cannot be correctly detected using the
                // cache prefill method.


                noPrefill.forEach(function (x) {
                    return delete cache[x];
                });
            }
            /**
             * Test if a property is supported, returns supported property with vendor
             * prefix if required. Returns `false` if not supported.
             *
             * @param {String} prop dash separated
             * @param {Object} [options]
             * @return {String|Boolean}
             * @api public
             */


            function supportedProperty(prop, options) {
                if (options === void 0) {
                    options = {};
                }

                // For server-side rendering.
                if (!el) return prop; // Remove cache for benchmark tests or return property from the cache.

                if (true && cache[prop] != null) {
                    return cache[prop];
                } // Check if 'transition' or 'transform' natively supported in browser.


                if (prop === 'transition' || prop === 'transform') {
                    options[prop] = prop in el.style;
                } // Find a plugin for current prefix property.


                for (var i = 0; i < propertyDetectors.length; i++) {
                    cache[prop] = propertyDetectors[i](prop, el.style, options); // Break loop, if value found.

                    if (cache[prop]) break;
                } // Reset styles for current property.
                // Firefox can even throw an error for invalid properties, e.g., "0".


                try {
                    el.style[prop] = '';
                } catch (err) {
                    return false;
                }

                return cache[prop];
            }

            var cache$1 = {};
            var transitionProperties = {
                transition: 1,
                'transition-property': 1,
                '-webkit-transition': 1,
                '-webkit-transition-property': 1
            };
            var transPropsRegExp = /(^\s*[\w-]+)|, (\s*[\w-]+)(?![^()]*\))/g;
            var el$1;
            /**
             * Returns prefixed value transition/transform if needed.
             *
             * @param {String} match
             * @param {String} p1
             * @param {String} p2
             * @return {String}
             * @api private
             */

            function prefixTransitionCallback(match, p1, p2) {
                if (p1 === 'var') return 'var';
                if (p1 === 'all') return 'all';
                if (p2 === 'all') return ', all';
                var prefixedValue = p1 ? supportedProperty(p1) : ", " + supportedProperty(p2);
                if (!prefixedValue) return p1 || p2;
                return prefixedValue;
            }

            if (is_in_browser__WEBPACK_IMPORTED_MODULE_0__["default"]) el$1 = document.createElement('p');
            /**
             * Returns prefixed value if needed. Returns `false` if value is not supported.
             *
             * @param {String} property
             * @param {String} value
             * @return {String|Boolean}
             * @api public
             */

            function supportedValue(property, value) {
                // For server-side rendering.
                var prefixedValue = value;
                if (!el$1 || property === 'content') return value; // It is a string or a number as a string like '1'.
                // We want only prefixable values here.
                // eslint-disable-next-line no-restricted-globals

                if (typeof prefixedValue !== 'string' || !isNaN(parseInt(prefixedValue, 10))) {
                    return prefixedValue;
                } // Create cache key for current value.


                var cacheKey = property + prefixedValue; // Remove cache for benchmark tests or return value from cache.

                if (true && cache$1[cacheKey] != null) {
                    return cache$1[cacheKey];
                } // IE can even throw an error in some cases, for e.g. style.content = 'bar'.


                try {
                    // Test value as it is.
                    el$1.style[property] = prefixedValue;
                } catch (err) {
                    // Return false if value not supported.
                    cache$1[cacheKey] = false;
                    return false;
                } // If 'transition' or 'transition-property' property.


                if (transitionProperties[property]) {
                    prefixedValue = prefixedValue.replace(transPropsRegExp, prefixTransitionCallback);
                } else if (el$1.style[property] === '') {
                    // Value with a vendor prefix.
                    prefixedValue = prefix.css + prefixedValue; // Hardcode test to convert "flex" to "-ms-flexbox" for IE10.

                    if (prefixedValue === '-ms-flex') el$1.style[property] = '-ms-flexbox'; // Test prefixed value.

                    el$1.style[property] = prefixedValue; // Return false if value not supported.

                    if (el$1.style[property] === '') {
                        cache$1[cacheKey] = false;
                        return false;
                    }
                } // Reset styles for current property.


                el$1.style[property] = ''; // Write current value to cache.

                cache$1[cacheKey] = prefixedValue;
                return cache$1[cacheKey];
            }




            /***/
        }),

/***/ "./node_modules/hyphenate-style-name/index.js":
/*!****************************************************!*\
  !*** ./node_modules/hyphenate-style-name/index.js ***!
  \****************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
            /* eslint-disable no-var, prefer-template */
            var uppercasePattern = /[A-Z]/g
            var msPattern = /^ms-/
            var cache = {}

            function toHyphenLower(match) {
                return '-' + match.toLowerCase()
            }

            function hyphenateStyleName(name) {
                if (cache.hasOwnProperty(name)) {
                    return cache[name]
                }

                var hName = name.replace(uppercasePattern, toHyphenLower)
                return (cache[name] = msPattern.test(hName) ? '-' + hName : hName)
            }

/* harmony default export */ __webpack_exports__["default"] = (hyphenateStyleName);


            /***/
        }),

/***/ "./node_modules/ieee754/index.js":
/*!***************************************!*\
  !*** ./node_modules/ieee754/index.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function (module, exports) {

            exports.read = function (buffer, offset, isLE, mLen, nBytes) {
                var e, m
                var eLen = (nBytes * 8) - mLen - 1
                var eMax = (1 << eLen) - 1
                var eBias = eMax >> 1
                var nBits = -7
                var i = isLE ? (nBytes - 1) : 0
                var d = isLE ? -1 : 1
                var s = buffer[offset + i]

                i += d

                e = s & ((1 << (-nBits)) - 1)
                s >>= (-nBits)
                nBits += eLen
                for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) { }

                m = e & ((1 << (-nBits)) - 1)
                e >>= (-nBits)
                nBits += mLen
                for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) { }

                if (e === 0) {
                    e = 1 - eBias
                } else if (e === eMax) {
                    return m ? NaN : ((s ? -1 : 1) * Infinity)
                } else {
                    m = m + Math.pow(2, mLen)
                    e = e - eBias
                }
                return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
            }

            exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
                var e, m, c
                var eLen = (nBytes * 8) - mLen - 1
                var eMax = (1 << eLen) - 1
                var eBias = eMax >> 1
                var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
                var i = isLE ? 0 : (nBytes - 1)
                var d = isLE ? 1 : -1
                var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

                value = Math.abs(value)

                if (isNaN(value) || value === Infinity) {
                    m = isNaN(value) ? 1 : 0
                    e = eMax
                } else {
                    e = Math.floor(Math.log(value) / Math.LN2)
                    if (value * (c = Math.pow(2, -e)) < 1) {
                        e--
                        c *= 2
                    }
                    if (e + eBias >= 1) {
                        value += rt / c
                    } else {
                        value += rt * Math.pow(2, 1 - eBias)
                    }
                    if (value * c >= 2) {
                        e++
                        c /= 2
                    }

                    if (e + eBias >= eMax) {
                        m = 0
                        e = eMax
                    } else if (e + eBias >= 1) {
                        m = ((value * c) - 1) * Math.pow(2, mLen)
                        e = e + eBias
                    } else {
                        m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
                        e = 0
                    }
                }

                for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) { }

                e = (e << mLen) | m
                eLen += mLen
                for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) { }

                buffer[offset + i - d] |= s * 128
            }


            /***/
        }),

/***/ "./node_modules/is-in-browser/dist/module.js":
/*!***************************************************!*\
  !*** ./node_modules/is-in-browser/dist/module.js ***!
  \***************************************************/
/*! exports provided: isBrowser, default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "isBrowser", function () { return isBrowser; });
            var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

            var isBrowser = (typeof window === "undefined" ? "undefined" : _typeof(window)) === "object" && (typeof document === "undefined" ? "undefined" : _typeof(document)) === 'object' && document.nodeType === 9;

/* harmony default export */ __webpack_exports__["default"] = (isBrowser);


            /***/
        }),

/***/ "./node_modules/isarray/index.js":
/*!***************************************!*\
  !*** ./node_modules/isarray/index.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function (module, exports) {

            var toString = {}.toString;

            module.exports = Array.isArray || function (arr) {
                return toString.call(arr) == '[object Array]';
            };


            /***/
        }),

/***/ "./node_modules/jss-plugin-camel-case/dist/jss-plugin-camel-case.esm.js":
/*!******************************************************************************!*\
  !*** ./node_modules/jss-plugin-camel-case/dist/jss-plugin-camel-case.esm.js ***!
  \******************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var hyphenate_style_name__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! hyphenate-style-name */ "./node_modules/hyphenate-style-name/index.js");


            /**
             * Convert camel cased property names to dash separated.
             *
             * @param {Object} style
             * @return {Object}
             */

            function convertCase(style) {
                var converted = {};

                for (var prop in style) {
                    var key = prop.indexOf('--') === 0 ? prop : Object(hyphenate_style_name__WEBPACK_IMPORTED_MODULE_0__["default"])(prop);
                    converted[key] = style[prop];
                }

                if (style.fallbacks) {
                    if (Array.isArray(style.fallbacks)) converted.fallbacks = style.fallbacks.map(convertCase); else converted.fallbacks = convertCase(style.fallbacks);
                }

                return converted;
            }
            /**
             * Allow camel cased property names by converting them back to dasherized.
             *
             * @param {Rule} rule
             */


            function camelCase() {
                function onProcessStyle(style) {
                    if (Array.isArray(style)) {
                        // Handle rules like @font-face, which can have multiple styles in an array
                        for (var index = 0; index < style.length; index++) {
                            style[index] = convertCase(style[index]);
                        }

                        return style;
                    }

                    return convertCase(style);
                }

                function onChangeValue(value, prop, rule) {
                    if (prop.indexOf('--') === 0) {
                        return value;
                    }

                    var hyphenatedProp = Object(hyphenate_style_name__WEBPACK_IMPORTED_MODULE_0__["default"])(prop); // There was no camel case in place

                    if (prop === hyphenatedProp) return value;
                    rule.prop(hyphenatedProp, value); // Core will ignore that property value we set the proper one above.

                    return null;
                }

                return {
                    onProcessStyle: onProcessStyle,
                    onChangeValue: onChangeValue
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (camelCase);


            /***/
        }),

/***/ "./node_modules/jss-plugin-compose/dist/jss-plugin-compose.esm.js":
/*!************************************************************************!*\
  !*** ./node_modules/jss-plugin-compose/dist/jss-plugin-compose.esm.js ***!
  \************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var tiny_warning__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tiny-warning */ "./node_modules/tiny-warning/dist/tiny-warning.esm.js");


            /**
             * Set selector.
             *
             * @param {Object} original rule
             * @param {String} className class string
             * @return {Boolean} flag, indicating function was successfull or not
             */
            function registerClass(rule, className) {
                // Skip falsy values
                if (!className) return true; // Support array of class names `{composes: ['foo', 'bar']}`

                if (Array.isArray(className)) {
                    for (var index = 0; index < className.length; index++) {
                        var isSetted = registerClass(rule, className[index]);
                        if (!isSetted) return false;
                    }

                    return true;
                } // Support space separated class names `{composes: 'foo bar'}`


                if (className.indexOf(' ') > -1) {
                    return registerClass(rule, className.split(' '));
                }

                var _ref = rule.options,
                    parent = _ref.parent; // It is a ref to a local rule.

                if (className[0] === '$') {
                    var refRule = parent.getRule(className.substr(1));

                    if (!refRule) {
                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_0__["default"])(false, "[JSS] Referenced rule is not defined. \n" + rule.toString()) : undefined;
                        return false;
                    }

                    if (refRule === rule) {
                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_0__["default"])(false, "[JSS] Cyclic composition detected. \n" + rule.toString()) : undefined;
                        return false;
                    }

                    parent.classes[rule.key] += " " + parent.classes[refRule.key];
                    return true;
                }

                parent.classes[rule.key] += " " + className;
                return true;
            }
            /**
             * Convert compose property to additional class, remove property from original styles.
             *
             * @param {Rule} rule
             * @api public
             */


            function jssCompose() {
                function onProcessStyle(style, rule) {
                    if (!('composes' in style)) return style;
                    registerClass(rule, style.composes); // Remove composes property to prevent infinite loop.

                    delete style.composes;
                    return style;
                }

                return {
                    onProcessStyle: onProcessStyle
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssCompose);


            /***/
        }),

/***/ "./node_modules/jss-plugin-default-unit/dist/jss-plugin-default-unit.esm.js":
/*!**********************************************************************************!*\
  !*** ./node_modules/jss-plugin-default-unit/dist/jss-plugin-default-unit.esm.js ***!
  \**********************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var jss__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");


            var px = jss__WEBPACK_IMPORTED_MODULE_0__["hasCSSTOMSupport"] && CSS ? CSS.px : 'px';
            var ms = jss__WEBPACK_IMPORTED_MODULE_0__["hasCSSTOMSupport"] && CSS ? CSS.ms : 'ms';
            var percent = jss__WEBPACK_IMPORTED_MODULE_0__["hasCSSTOMSupport"] && CSS ? CSS.percent : '%';
            /**
             * Generated jss-plugin-default-unit CSS property units
             *
             * @type object
             */

            var defaultUnits = {
                // Animation properties
                'animation-delay': ms,
                'animation-duration': ms,
                // Background properties
                'background-position': px,
                'background-position-x': px,
                'background-position-y': px,
                'background-size': px,
                // Border Properties
                border: px,
                'border-bottom': px,
                'border-bottom-left-radius': px,
                'border-bottom-right-radius': px,
                'border-bottom-width': px,
                'border-left': px,
                'border-left-width': px,
                'border-radius': px,
                'border-right': px,
                'border-right-width': px,
                'border-top': px,
                'border-top-left-radius': px,
                'border-top-right-radius': px,
                'border-top-width': px,
                'border-width': px,
                // Margin properties
                margin: px,
                'margin-bottom': px,
                'margin-left': px,
                'margin-right': px,
                'margin-top': px,
                // Padding properties
                padding: px,
                'padding-bottom': px,
                'padding-left': px,
                'padding-right': px,
                'padding-top': px,
                // Mask properties
                'mask-position-x': px,
                'mask-position-y': px,
                'mask-size': px,
                // Width and height properties
                height: px,
                width: px,
                'min-height': px,
                'max-height': px,
                'min-width': px,
                'max-width': px,
                // Position properties
                bottom: px,
                left: px,
                top: px,
                right: px,
                // Shadow properties
                'box-shadow': px,
                'text-shadow': px,
                // Column properties
                'column-gap': px,
                'column-rule': px,
                'column-rule-width': px,
                'column-width': px,
                // Font and text properties
                'font-size': px,
                'font-size-delta': px,
                'letter-spacing': px,
                'text-indent': px,
                'text-stroke': px,
                'text-stroke-width': px,
                'word-spacing': px,
                // Motion properties
                motion: px,
                'motion-offset': px,
                // Outline properties
                outline: px,
                'outline-offset': px,
                'outline-width': px,
                // Perspective properties
                perspective: px,
                'perspective-origin-x': percent,
                'perspective-origin-y': percent,
                // Transform properties
                'transform-origin': percent,
                'transform-origin-x': percent,
                'transform-origin-y': percent,
                'transform-origin-z': percent,
                // Transition properties
                'transition-delay': ms,
                'transition-duration': ms,
                // Alignment properties
                'vertical-align': px,
                'flex-basis': px,
                // Some random properties
                'shape-margin': px,
                size: px,
                // Grid properties
                grid: px,
                'grid-gap': px,
                'grid-row-gap': px,
                'grid-column-gap': px,
                'grid-template-rows': px,
                'grid-template-columns': px,
                'grid-auto-rows': px,
                'grid-auto-columns': px,
                // Not existing properties.
                // Used to avoid issues with jss-plugin-expand integration.
                'box-shadow-x': px,
                'box-shadow-y': px,
                'box-shadow-blur': px,
                'box-shadow-spread': px,
                'font-line-height': px,
                'text-shadow-x': px,
                'text-shadow-y': px,
                'text-shadow-blur': px
            };

            /**
             * Clones the object and adds a camel cased property version.
             */
            function addCamelCasedVersion(obj) {
                var regExp = /(-[a-z])/g;

                var replace = function replace(str) {
                    return str[1].toUpperCase();
                };

                var newObj = {};

                for (var _key in obj) {
                    newObj[_key] = obj[_key];
                    newObj[_key.replace(regExp, replace)] = obj[_key];
                }

                return newObj;
            }

            var units = addCamelCasedVersion(defaultUnits);
            /**
             * Recursive deep style passing function
             */

            function iterate(prop, value, options) {
                if (!value) return value;

                if (Array.isArray(value)) {
                    for (var i = 0; i < value.length; i++) {
                        value[i] = iterate(prop, value[i], options);
                    }
                } else if (typeof value === 'object') {
                    if (prop === 'fallbacks') {
                        for (var innerProp in value) {
                            value[innerProp] = iterate(innerProp, value[innerProp], options);
                        }
                    } else {
                        for (var _innerProp in value) {
                            value[_innerProp] = iterate(prop + "-" + _innerProp, value[_innerProp], options);
                        }
                    }
                } else if (typeof value === 'number') {
                    if (options[prop]) {
                        return "" + value + options[prop];
                    }

                    if (units[prop]) {
                        return typeof units[prop] === 'function' ? units[prop](value).toString() : "" + value + units[prop];
                    }

                    return value.toString();
                }

                return value;
            }
            /**
             * Add unit to numeric values.
             */


            function defaultUnit(options) {
                if (options === void 0) {
                    options = {};
                }

                var camelCasedOptions = addCamelCasedVersion(options);

                function onProcessStyle(style, rule) {
                    if (rule.type !== 'style') return style;

                    for (var prop in style) {
                        style[prop] = iterate(prop, style[prop], camelCasedOptions);
                    }

                    return style;
                }

                function onChangeValue(value, prop) {
                    return iterate(prop, value, camelCasedOptions);
                }

                return {
                    onProcessStyle: onProcessStyle,
                    onChangeValue: onChangeValue
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (defaultUnit);


            /***/
        }),

/***/ "./node_modules/jss-plugin-expand/dist/jss-plugin-expand.esm.js":
/*!**********************************************************************!*\
  !*** ./node_modules/jss-plugin-expand/dist/jss-plugin-expand.esm.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
            /**
             * A scheme for converting properties from array to regular style.
             * All properties listed below will be transformed to a string separated by space.
             */
            var propArray = {
                'background-size': true,
                'background-position': true,
                border: true,
                'border-bottom': true,
                'border-left': true,
                'border-top': true,
                'border-right': true,
                'border-radius': true,
                'border-image': true,
                'border-width': true,
                'border-style': true,
                'border-color': true,
                'box-shadow': true,
                flex: true,
                margin: true,
                padding: true,
                outline: true,
                'transform-origin': true,
                transform: true,
                transition: true
                /**
                 * A scheme for converting arrays to regular styles inside of objects.
                 * For e.g.: "{position: [0, 0]}" => "background-position: 0 0;".
                 */

            };
            var propArrayInObj = {
                position: true,
                // background-position
                size: true // background-size

                /**
                 * A scheme for parsing and building correct styles from passed objects.
                 */

            };
            var propObj = {
                padding: {
                    top: 0,
                    right: 0,
                    bottom: 0,
                    left: 0
                },
                margin: {
                    top: 0,
                    right: 0,
                    bottom: 0,
                    left: 0
                },
                background: {
                    attachment: null,
                    color: null,
                    image: null,
                    position: null,
                    repeat: null
                },
                border: {
                    width: null,
                    style: null,
                    color: null
                },
                'border-top': {
                    width: null,
                    style: null,
                    color: null
                },
                'border-right': {
                    width: null,
                    style: null,
                    color: null
                },
                'border-bottom': {
                    width: null,
                    style: null,
                    color: null
                },
                'border-left': {
                    width: null,
                    style: null,
                    color: null
                },
                outline: {
                    width: null,
                    style: null,
                    color: null
                },
                'list-style': {
                    type: null,
                    position: null,
                    image: null
                },
                transition: {
                    property: null,
                    duration: null,
                    'timing-function': null,
                    timingFunction: null,
                    // Needed for avoiding comilation issues with jss-plugin-camel-case
                    delay: null
                },
                animation: {
                    name: null,
                    duration: null,
                    'timing-function': null,
                    timingFunction: null,
                    // Needed to avoid compilation issues with jss-plugin-camel-case
                    delay: null,
                    'iteration-count': null,
                    iterationCount: null,
                    // Needed to avoid compilation issues with jss-plugin-camel-case
                    direction: null,
                    'fill-mode': null,
                    fillMode: null,
                    // Needed to avoid compilation issues with jss-plugin-camel-case
                    'play-state': null,
                    playState: null // Needed to avoid compilation issues with jss-plugin-camel-case

                },
                'box-shadow': {
                    x: 0,
                    y: 0,
                    blur: 0,
                    spread: 0,
                    color: null,
                    inset: null
                },
                'text-shadow': {
                    x: 0,
                    y: 0,
                    blur: null,
                    color: null
                }
                /**
                 * A scheme for converting non-standart properties inside object.
                 * For e.g.: include 'border-radius' property inside 'border' object.
                 */

            };
            var customPropObj = {
                border: {
                    radius: 'border-radius',
                    image: 'border-image',
                    width: 'border-width',
                    style: 'border-style',
                    color: 'border-color'
                },
                'border-bottom': {
                    width: 'border-bottom-width',
                    style: 'border-bottom-style',
                    color: 'border-bottom-color'
                },
                'border-top': {
                    width: 'border-top-width',
                    style: 'border-top-style',
                    color: 'border-top-color'
                },
                'border-left': {
                    width: 'border-left-width',
                    style: 'border-left-style',
                    color: 'border-left-color'
                },
                'border-right': {
                    width: 'border-right-width',
                    style: 'border-right-style',
                    color: 'border-right-color'
                },
                background: {
                    size: 'background-size',
                    image: 'background-image'
                },
                font: {
                    style: 'font-style',
                    variant: 'font-variant',
                    weight: 'font-weight',
                    stretch: 'font-stretch',
                    size: 'font-size',
                    family: 'font-family',
                    lineHeight: 'line-height',
                    // Needed to avoid compilation issues with jss-plugin-camel-case
                    'line-height': 'line-height'
                },
                flex: {
                    grow: 'flex-grow',
                    basis: 'flex-basis',
                    direction: 'flex-direction',
                    wrap: 'flex-wrap',
                    flow: 'flex-flow',
                    shrink: 'flex-shrink'
                },
                align: {
                    self: 'align-self',
                    items: 'align-items',
                    content: 'align-content'
                },
                grid: {
                    'template-columns': 'grid-template-columns',
                    templateColumns: 'grid-template-columns',
                    'template-rows': 'grid-template-rows',
                    templateRows: 'grid-template-rows',
                    'template-areas': 'grid-template-areas',
                    templateAreas: 'grid-template-areas',
                    template: 'grid-template',
                    'auto-columns': 'grid-auto-columns',
                    autoColumns: 'grid-auto-columns',
                    'auto-rows': 'grid-auto-rows',
                    autoRows: 'grid-auto-rows',
                    'auto-flow': 'grid-auto-flow',
                    autoFlow: 'grid-auto-flow',
                    row: 'grid-row',
                    column: 'grid-column',
                    'row-start': 'grid-row-start',
                    rowStart: 'grid-row-start',
                    'row-end': 'grid-row-end',
                    rowEnd: 'grid-row-end',
                    'column-start': 'grid-column-start',
                    columnStart: 'grid-column-start',
                    'column-end': 'grid-column-end',
                    columnEnd: 'grid-column-end',
                    area: 'grid-area',
                    gap: 'grid-gap',
                    'row-gap': 'grid-row-gap',
                    rowGap: 'grid-row-gap',
                    'column-gap': 'grid-column-gap',
                    columnGap: 'grid-column-gap'
                }
            };

            /* eslint-disable no-use-before-define */

            /**
             * Map values by given prop.
             *
             * @param {Array} array of values
             * @param {String} original property
             * @param {String} original rule
             * @return {String} mapped values
             */
            function mapValuesByProp(value, prop, rule) {
                return value.map(function (item) {
                    return objectToArray(item, prop, rule, false, true);
                });
            }
            /**
             * Convert array to nested array, if needed
             */


            function processArray(value, prop, scheme, rule) {
                if (scheme[prop] == null) return value;
                if (value.length === 0) return [];
                if (Array.isArray(value[0])) return processArray(value[0], prop, scheme, rule);

                if (typeof value[0] === 'object') {
                    return mapValuesByProp(value, prop, rule);
                }

                return [value];
            }
            /**
             * Convert object to array.
             */


            function objectToArray(value, prop, rule, isFallback, isInArray) {
                if (!(propObj[prop] || customPropObj[prop])) return [];
                var result = []; // Check if exists any non-standard property

                if (customPropObj[prop]) {
                    // eslint-disable-next-line no-param-reassign
                    value = customPropsToStyle(value, rule, customPropObj[prop], isFallback);
                } // Pass throught all standart props


                if (Object.keys(value).length) {
                    for (var baseProp in propObj[prop]) {
                        if (value[baseProp]) {
                            if (Array.isArray(value[baseProp])) {
                                result.push(propArrayInObj[baseProp] === null ? value[baseProp] : value[baseProp].join(' '));
                            } else result.push(value[baseProp]);

                            continue;
                        } // Add default value from props config.


                        if (propObj[prop][baseProp] != null) {
                            result.push(propObj[prop][baseProp]);
                        }
                    }
                }

                if (!result.length || isInArray) return result;
                return [result];
            }
            /**
             * Convert custom properties values to styles adding them to rule directly
             */


            function customPropsToStyle(value, rule, customProps, isFallback) {
                for (var prop in customProps) {
                    var propName = customProps[prop]; // If current property doesn't exist already in rule - add new one

                    if (typeof value[prop] !== 'undefined' && (isFallback || !rule.prop(propName))) {
                        var _styleDetector;

                        var appendedValue = styleDetector((_styleDetector = {}, _styleDetector[propName] = value[prop], _styleDetector), rule)[propName]; // Add style directly in rule

                        if (isFallback) rule.style.fallbacks[propName] = appendedValue; else rule.style[propName] = appendedValue;
                    } // Delete converted property to avoid double converting


                    delete value[prop];
                }

                return value;
            }
            /**
             * Detect if a style needs to be converted.
             */


            function styleDetector(style, rule, isFallback) {
                for (var prop in style) {
                    var value = style[prop];

                    if (Array.isArray(value)) {
                        // Check double arrays to avoid recursion.
                        if (!Array.isArray(value[0])) {
                            if (prop === 'fallbacks') {
                                for (var index = 0; index < style.fallbacks.length; index++) {
                                    style.fallbacks[index] = styleDetector(style.fallbacks[index], rule, true);
                                }

                                continue;
                            }

                            style[prop] = processArray(value, prop, propArray, rule); // Avoid creating properties with empty values

                            if (!style[prop].length) delete style[prop];
                        }
                    } else if (typeof value === 'object') {
                        if (prop === 'fallbacks') {
                            style.fallbacks = styleDetector(style.fallbacks, rule, true);
                            continue;
                        }

                        style[prop] = objectToArray(value, prop, rule, isFallback); // Avoid creating properties with empty values

                        if (!style[prop].length) delete style[prop];
                    } // Maybe a computed value resulting in an empty string
                    else if (style[prop] === '') delete style[prop];
                }

                return style;
            }
            /**
             * Adds possibility to write expanded styles.
             */


            function jssExpand() {
                function onProcessStyle(style, rule) {
                    if (!style || rule.type !== 'style') return style;

                    if (Array.isArray(style)) {
                        // Pass rules one by one and reformat them
                        for (var index = 0; index < style.length; index++) {
                            style[index] = styleDetector(style[index], rule);
                        }

                        return style;
                    }

                    return styleDetector(style, rule);
                }

                return {
                    onProcessStyle: onProcessStyle
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssExpand);


            /***/
        }),

/***/ "./node_modules/jss-plugin-extend/dist/jss-plugin-extend.esm.js":
/*!**********************************************************************!*\
  !*** ./node_modules/jss-plugin-extend/dist/jss-plugin-extend.esm.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var tiny_warning__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tiny-warning */ "./node_modules/tiny-warning/dist/tiny-warning.esm.js");


            /* eslint-disable no-use-before-define */

            var isObject = function isObject(obj) {
                return obj && typeof obj === 'object' && !Array.isArray(obj);
            };

            var valueNs = "extendCurrValue" + Date.now();

            function mergeExtend(style, rule, sheet, newStyle) {
                var extendType = typeof style.extend; // Extend using a rule name.

                if (extendType === 'string') {
                    if (!sheet) return;
                    var refRule = sheet.getRule(style.extend);
                    if (!refRule) return;

                    if (refRule === rule) {
                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_0__["default"])(false, "[JSS] A rule tries to extend itself \n" + rule.toString()) : undefined;
                        return;
                    }

                    var parent = refRule.options.parent;

                    if (parent) {
                        var originalStyle = parent.rules.raw[style.extend];
                        extend(originalStyle, rule, sheet, newStyle);
                    }

                    return;
                } // Extend using an array of objects.


                if (Array.isArray(style.extend)) {
                    for (var index = 0; index < style.extend.length; index++) {
                        extend(style.extend[index], rule, sheet, newStyle);
                    }

                    return;
                } // Extend is a style object.


                for (var prop in style.extend) {
                    if (prop === 'extend') {
                        extend(style.extend.extend, rule, sheet, newStyle);
                        continue;
                    }

                    if (isObject(style.extend[prop])) {
                        if (!(prop in newStyle)) newStyle[prop] = {};
                        extend(style.extend[prop], rule, sheet, newStyle[prop]);
                        continue;
                    }

                    newStyle[prop] = style.extend[prop];
                }
            }

            function mergeRest(style, rule, sheet, newStyle) {
                // Copy base style.
                for (var prop in style) {
                    if (prop === 'extend') continue;

                    if (isObject(newStyle[prop]) && isObject(style[prop])) {
                        extend(style[prop], rule, sheet, newStyle[prop]);
                        continue;
                    }

                    if (isObject(style[prop])) {
                        newStyle[prop] = extend(style[prop], rule, sheet);
                        continue;
                    }

                    newStyle[prop] = style[prop];
                }
            }
            /**
             * Recursively extend styles.
             */


            function extend(style, rule, sheet, newStyle) {
                if (newStyle === void 0) {
                    newStyle = {};
                }

                mergeExtend(style, rule, sheet, newStyle);
                mergeRest(style, rule, sheet, newStyle);
                return newStyle;
            }
            /**
             * Handle `extend` property.
             *
             * @param {Rule} rule
             * @api public
             */


            function jssExtend() {
                function onProcessStyle(style, rule, sheet) {
                    if ('extend' in style) return extend(style, rule, sheet);
                    return style;
                }

                function onChangeValue(value, prop, rule) {
                    if (prop !== 'extend') return value; // Value is empty, remove properties set previously.

                    if (value == null || value === false) {
                        // $FlowFixMe: Flow complains because there is no indexer property in StyleRule
                        for (var key in rule[valueNs]) {
                            rule.prop(key, null);
                        } // $FlowFixMe: Flow complains because there is no indexer property in StyleRule


                        rule[valueNs] = null;
                        return null;
                    }

                    if (typeof value === 'object') {
                        // $FlowFixMe: This will be an object
                        for (var _key in value) {
                            rule.prop(_key, value[_key]);
                        } // $FlowFixMe: Flow complains because there is no indexer property in StyleRule


                        rule[valueNs] = value;
                    } // Make sure we don't set the value in the core.


                    return null;
                }

                return {
                    onProcessStyle: onProcessStyle,
                    onChangeValue: onChangeValue
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssExtend);


            /***/
        }),

/***/ "./node_modules/jss-plugin-global/dist/jss-plugin-global.esm.js":
/*!**********************************************************************!*\
  !*** ./node_modules/jss-plugin-global/dist/jss-plugin-global.esm.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var _babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @babel/runtime/helpers/esm/extends */ "./node_modules/@babel/runtime/helpers/esm/extends.js");
/* harmony import */ var jss__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");



            var at = '@global';
            var atPrefix = '@global ';

            var GlobalContainerRule =
                /*#__PURE__*/
                function () {
                    function GlobalContainerRule(key, styles, options) {
                        this.type = 'global';
                        this.at = at;
                        this.rules = void 0;
                        this.options = void 0;
                        this.key = void 0;
                        this.isProcessed = false;
                        this.key = key;
                        this.options = options;
                        this.rules = new jss__WEBPACK_IMPORTED_MODULE_1__["RuleList"](Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            parent: this
                        }));

                        for (var selector in styles) {
                            this.rules.add(selector, styles[selector]);
                        }

                        this.rules.process();
                    }
                    /**
                     * Get a rule.
                     */


                    var _proto = GlobalContainerRule.prototype;

                    _proto.getRule = function getRule(name) {
                        return this.rules.get(name);
                    }
                        /**
                         * Create and register rule, run plugins.
                         */
                        ;

                    _proto.addRule = function addRule(name, style, options) {
                        var rule = this.rules.add(name, style, options);
                        this.options.jss.plugins.onProcessRule(rule);
                        return rule;
                    }
                        /**
                         * Get index of a rule.
                         */
                        ;

                    _proto.indexOf = function indexOf(rule) {
                        return this.rules.indexOf(rule);
                    }
                        /**
                         * Generates a CSS string.
                         */
                        ;

                    _proto.toString = function toString() {
                        return this.rules.toString();
                    };

                    return GlobalContainerRule;
                }();

            var GlobalPrefixedRule =
                /*#__PURE__*/
                function () {
                    function GlobalPrefixedRule(key, style, options) {
                        this.type = 'global';
                        this.at = at;
                        this.options = void 0;
                        this.rule = void 0;
                        this.isProcessed = false;
                        this.key = void 0;
                        this.key = key;
                        this.options = options;
                        var selector = key.substr(atPrefix.length);
                        this.rule = options.jss.createRule(selector, style, Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            parent: this
                        }));
                    }

                    var _proto2 = GlobalPrefixedRule.prototype;

                    _proto2.toString = function toString(options) {
                        return this.rule ? this.rule.toString(options) : '';
                    };

                    return GlobalPrefixedRule;
                }();

            var separatorRegExp = /\s*,\s*/g;

            function addScope(selector, scope) {
                var parts = selector.split(separatorRegExp);
                var scoped = '';

                for (var i = 0; i < parts.length; i++) {
                    scoped += scope + " " + parts[i].trim();
                    if (parts[i + 1]) scoped += ', ';
                }

                return scoped;
            }

            function handleNestedGlobalContainerRule(rule) {
                var options = rule.options,
                    style = rule.style;
                var rules = style ? style[at] : null;
                if (!rules) return;

                for (var name in rules) {
                    options.sheet.addRule(name, rules[name], Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                        selector: addScope(name, rule.selector)
                    }));
                }

                delete style[at];
            }

            function handlePrefixedGlobalRule(rule) {
                var options = rule.options,
                    style = rule.style;

                for (var prop in style) {
                    if (prop[0] !== '@' || prop.substr(0, at.length) !== at) continue;
                    var selector = addScope(prop.substr(at.length), rule.selector);
                    options.sheet.addRule(selector, style[prop], Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                        selector: selector
                    }));
                    delete style[prop];
                }
            }
            /**
             * Convert nested rules to separate, remove them from original styles.
             *
             * @param {Rule} rule
             * @api public
             */


            function jssGlobal() {
                function onCreateRule(name, styles, options) {
                    if (!name) return null;

                    if (name === at) {
                        return new GlobalContainerRule(name, styles, options);
                    }

                    if (name[0] === '@' && name.substr(0, atPrefix.length) === atPrefix) {
                        return new GlobalPrefixedRule(name, styles, options);
                    }

                    var parent = options.parent;

                    if (parent) {
                        if (parent.type === 'global' || parent.options.parent && parent.options.parent.type === 'global') {
                            options.scoped = false;
                        }
                    }

                    if (options.scoped === false) {
                        options.selector = name;
                    }

                    return null;
                }

                function onProcessRule(rule) {
                    if (rule.type !== 'style') return;
                    handleNestedGlobalContainerRule(rule);
                    handlePrefixedGlobalRule(rule);
                }

                return {
                    onCreateRule: onCreateRule,
                    onProcessRule: onProcessRule
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssGlobal);


            /***/
        }),

/***/ "./node_modules/jss-plugin-nested/dist/jss-plugin-nested.esm.js":
/*!**********************************************************************!*\
  !*** ./node_modules/jss-plugin-nested/dist/jss-plugin-nested.esm.js ***!
  \**********************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var _babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @babel/runtime/helpers/esm/extends */ "./node_modules/@babel/runtime/helpers/esm/extends.js");
/* harmony import */ var tiny_warning__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tiny-warning */ "./node_modules/tiny-warning/dist/tiny-warning.esm.js");



            var separatorRegExp = /\s*,\s*/g;
            var parentRegExp = /&/g;
            var refRegExp = /\$([\w-]+)/g;
            /**
             * Convert nested rules to separate, remove them from original styles.
             *
             * @param {Rule} rule
             * @api public
             */

            function jssNested() {
                // Get a function to be used for $ref replacement.
                function getReplaceRef(container, sheet) {
                    return function (match, key) {
                        var rule = container.getRule(key) || sheet && sheet.getRule(key);

                        if (rule) {
                            rule = rule;
                            return rule.selector;
                        }

                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_1__["default"])(false, "[JSS] Could not find the referenced rule \"" + key + "\" in \"" + (container.options.meta || container.toString()) + "\".") : undefined;
                        return key;
                    };
                }

                function replaceParentRefs(nestedProp, parentProp) {
                    var parentSelectors = parentProp.split(separatorRegExp);
                    var nestedSelectors = nestedProp.split(separatorRegExp);
                    var result = '';

                    for (var i = 0; i < parentSelectors.length; i++) {
                        var parent = parentSelectors[i];

                        for (var j = 0; j < nestedSelectors.length; j++) {
                            var nested = nestedSelectors[j];
                            if (result) result += ', '; // Replace all & by the parent or prefix & with the parent.

                            result += nested.indexOf('&') !== -1 ? nested.replace(parentRegExp, parent) : parent + " " + nested;
                        }
                    }

                    return result;
                }

                function getOptions(rule, container, options) {
                    // Options has been already created, now we only increase index.
                    if (options) return Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                        index: options.index + 1
                    });
                    var nestingLevel = rule.options.nestingLevel;
                    nestingLevel = nestingLevel === undefined ? 1 : nestingLevel + 1;
                    return Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, rule.options, {
                        nestingLevel: nestingLevel,
                        index: container.indexOf(rule) + 1
                    });
                }

                function onProcessStyle(style, rule, sheet) {
                    if (rule.type !== 'style') return style;
                    var styleRule = rule;
                    var container = styleRule.options.parent;
                    var options;
                    var replaceRef;

                    for (var prop in style) {
                        var isNested = prop.indexOf('&') !== -1;
                        var isNestedConditional = prop[0] === '@';
                        if (!isNested && !isNestedConditional) continue;
                        options = getOptions(styleRule, container, options);

                        if (isNested) {
                            var selector = replaceParentRefs(prop, styleRule.selector); // Lazily create the ref replacer function just once for
                            // all nested rules within the sheet.

                            if (!replaceRef) replaceRef = getReplaceRef(container, sheet); // Replace all $refs.

                            selector = selector.replace(refRegExp, replaceRef);
                            container.addRule(selector, style[prop], Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                                selector: selector
                            }));
                        } else if (isNestedConditional) {
                            // Place conditional right after the parent rule to ensure right ordering.
                            container.addRule(prop, {}, options) // Flow expects more options but they aren't required
                                // And flow doesn't know this will always be a StyleRule which has the addRule method
                                // $FlowFixMe
                                .addRule(styleRule.key, style[prop], {
                                    selector: styleRule.selector
                                });
                        }

                        delete style[prop];
                    }

                    return style;
                }

                return {
                    onProcessStyle: onProcessStyle
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssNested);


            /***/
        }),

/***/ "./node_modules/jss-plugin-props-sort/dist/jss-plugin-props-sort.esm.js":
/*!******************************************************************************!*\
  !*** ./node_modules/jss-plugin-props-sort/dist/jss-plugin-props-sort.esm.js ***!
  \******************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
            /**
             * Sort props by length.
             */
            function jssPropsSort() {
                var sort = function sort(prop0, prop1) {
                    if (prop0.length === prop1.length) {
                        return prop0 > prop1 ? 1 : -1;
                    }

                    return prop0.length - prop1.length;
                };

                return {
                    onProcessStyle: function onProcessStyle(style, rule) {
                        if (rule.type !== 'style') return style;
                        var newStyle = {};
                        var props = Object.keys(style).sort(sort);

                        for (var i = 0; i < props.length; i++) {
                            newStyle[props[i]] = style[props[i]];
                        }

                        return newStyle;
                    }
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssPropsSort);


            /***/
        }),

/***/ "./node_modules/jss-plugin-rule-value-function/dist/jss-plugin-rule-value-function.esm.js":
/*!************************************************************************************************!*\
  !*** ./node_modules/jss-plugin-rule-value-function/dist/jss-plugin-rule-value-function.esm.js ***!
  \************************************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var jss__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");


            var now = Date.now();
            var fnValuesNs = "fnValues" + now;
            var fnRuleNs = "fnStyle" + ++now;
            function functionPlugin() {
                return {
                    onCreateRule: function onCreateRule(name, decl, options) {
                        if (typeof decl !== 'function') return null;
                        var rule = Object(jss__WEBPACK_IMPORTED_MODULE_0__["createRule"])(name, {}, options);
                        rule[fnRuleNs] = decl;
                        return rule;
                    },
                    onProcessStyle: function onProcessStyle(style, rule) {
                        // We need to extract function values from the declaration, so that we can keep core unaware of them.
                        // We need to do that only once.
                        // We don't need to extract functions on each style update, since this can happen only once.
                        // We don't support function values inside of function rules.
                        if (fnValuesNs in rule || fnRuleNs in rule) return style;
                        var fnValues = {};

                        for (var prop in style) {
                            var value = style[prop];
                            if (typeof value !== 'function') continue;
                            delete style[prop];
                            fnValues[prop] = value;
                        } // $FlowFixMe


                        rule[fnValuesNs] = fnValues;
                        return style;
                    },
                    onUpdate: function onUpdate(data, rule, sheet, options) {
                        var styleRule = rule;
                        var fnRule = styleRule[fnRuleNs]; // If we have a style function, the entire rule is dynamic and style object
                        // will be returned from that function.

                        if (fnRule) {
                            // Empty object will remove all currently defined props
                            // in case function rule returns a falsy value.
                            styleRule.style = fnRule(data) || {};
                        }

                        var fnValues = styleRule[fnValuesNs]; // If we have a fn values map, it is a rule with function values.

                        if (fnValues) {
                            for (var prop in fnValues) {
                                styleRule.prop(prop, fnValues[prop](data), options);
                            }
                        }
                    }
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (functionPlugin);


            /***/
        }),

/***/ "./node_modules/jss-plugin-rule-value-observable/dist/jss-plugin-rule-value-observable.esm.js":
/*!****************************************************************************************************!*\
  !*** ./node_modules/jss-plugin-rule-value-observable/dist/jss-plugin-rule-value-observable.esm.js ***!
  \****************************************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var symbol_observable__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! symbol-observable */ "./node_modules/symbol-observable/es/index.js");
/* harmony import */ var jss__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");



            var isObservable = function isObservable(value) {
                return value && value[symbol_observable__WEBPACK_IMPORTED_MODULE_0__["default"]] && value === value[symbol_observable__WEBPACK_IMPORTED_MODULE_0__["default"]]();
            };

            function observablePlugin(updateOptions) {
                return {
                    onCreateRule: function onCreateRule(name, decl, options) {
                        if (!isObservable(decl)) return null; // Cast `decl` to `Observable`, since it passed the type guard.

                        var style$ = decl;
                        var rule = Object(jss__WEBPACK_IMPORTED_MODULE_1__["createRule"])(name, {}, options); // TODO
                        // Call `stream.subscribe()` returns a subscription, which should be explicitly
                        // unsubscribed from when we know this sheet is no longer needed.

                        style$.subscribe(function (style) {
                            for (var prop in style) {
                                rule.prop(prop, style[prop], updateOptions);
                            }
                        });
                        return rule;
                    },
                    onProcessRule: function onProcessRule(rule) {
                        if (rule && rule.type !== 'style') return;
                        var styleRule = rule;
                        var style = styleRule.style;

                        var _loop = function _loop(prop) {
                            var value = style[prop];
                            if (!isObservable(value)) return "continue";
                            delete style[prop];
                            value.subscribe({
                                next: function next(nextValue) {
                                    styleRule.prop(prop, nextValue, updateOptions);
                                }
                            });
                        };

                        for (var prop in style) {
                            var _ret = _loop(prop);

                            if (_ret === "continue") continue;
                        }
                    }
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (observablePlugin);


            /***/
        }),

/***/ "./node_modules/jss-plugin-template/dist/jss-plugin-template.esm.js":
/*!**************************************************************************!*\
  !*** ./node_modules/jss-plugin-template/dist/jss-plugin-template.esm.js ***!
  \**************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var tiny_warning__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tiny-warning */ "./node_modules/tiny-warning/dist/tiny-warning.esm.js");


            var semiWithNl = /;\n/;
            /**
             * Naive CSS parser.
             * - Supports only rule body (no selectors)
             * - Requires semicolon and new line after the value (except of last line)
             * - No nested rules support
             */

            var parse = (function (cssText) {
                var style = {};
                var split = cssText.split(semiWithNl);

                for (var i = 0; i < split.length; i++) {
                    var decl = (split[i] || '').trim();
                    if (!decl) continue;
                    var colonIndex = decl.indexOf(':');

                    if (colonIndex === -1) {
                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_0__["default"])(false, "[JSS] Malformed CSS string \"" + decl + "\"") : undefined;
                        continue;
                    }

                    var prop = decl.substr(0, colonIndex).trim();
                    var value = decl.substr(colonIndex + 1).trim();
                    style[prop] = value;
                }

                return style;
            });

            var onProcessRule = function onProcessRule(rule) {
                if (typeof rule.style === 'string') {
                    // $FlowFixMe: We can safely assume that rule has the style property
                    rule.style = parse(rule.style);
                }
            };

            function templatePlugin() {
                return {
                    onProcessRule: onProcessRule
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (templatePlugin);


            /***/
        }),

/***/ "./node_modules/jss-plugin-vendor-prefixer/dist/jss-plugin-vendor-prefixer.esm.js":
/*!****************************************************************************************!*\
  !*** ./node_modules/jss-plugin-vendor-prefixer/dist/jss-plugin-vendor-prefixer.esm.js ***!
  \****************************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var css_vendor__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! css-vendor */ "./node_modules/css-vendor/dist/css-vendor.esm.js");
/* harmony import */ var jss__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jss */ "./node_modules/jss/dist/jss.esm.js");



            /**
             * Add vendor prefix to a property name when needed.
             *
             * @api public
             */

            function jssVendorPrefixer() {
                function onProcessRule(rule) {
                    if (rule.type === 'keyframes') {
                        var atRule = rule;
                        atRule.at = Object(css_vendor__WEBPACK_IMPORTED_MODULE_0__["supportedKeyframes"])(atRule.at);
                    }
                }

                function prefixStyle(style) {
                    for (var prop in style) {
                        var value = style[prop];

                        if (prop === 'fallbacks' && Array.isArray(value)) {
                            style[prop] = value.map(prefixStyle);
                            continue;
                        }

                        var changeProp = false;
                        var supportedProp = Object(css_vendor__WEBPACK_IMPORTED_MODULE_0__["supportedProperty"])(prop);
                        if (supportedProp && supportedProp !== prop) changeProp = true;
                        var changeValue = false;
                        var supportedValue$$1 = Object(css_vendor__WEBPACK_IMPORTED_MODULE_0__["supportedValue"])(supportedProp, Object(jss__WEBPACK_IMPORTED_MODULE_1__["toCssValue"])(value));
                        if (supportedValue$$1 && supportedValue$$1 !== value) changeValue = true;

                        if (changeProp || changeValue) {
                            if (changeProp) delete style[prop];
                            style[supportedProp || prop] = supportedValue$$1 || value;
                        }
                    }

                    return style;
                }

                function onProcessStyle(style, rule) {
                    if (rule.type !== 'style') return style;
                    return prefixStyle(style);
                }

                function onChangeValue(value, prop) {
                    return Object(css_vendor__WEBPACK_IMPORTED_MODULE_0__["supportedValue"])(prop, Object(jss__WEBPACK_IMPORTED_MODULE_1__["toCssValue"])(value)) || value;
                }

                return {
                    onProcessRule: onProcessRule,
                    onProcessStyle: onProcessStyle,
                    onChangeValue: onChangeValue
                };
            }

/* harmony default export */ __webpack_exports__["default"] = (jssVendorPrefixer);


            /***/
        }),

/***/ "./node_modules/jss-preset-default/dist/jss-preset-default.esm.js":
/*!************************************************************************!*\
  !*** ./node_modules/jss-preset-default/dist/jss-preset-default.esm.js ***!
  \************************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony import */ var jss_plugin_rule_value_function__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jss-plugin-rule-value-function */ "./node_modules/jss-plugin-rule-value-function/dist/jss-plugin-rule-value-function.esm.js");
/* harmony import */ var jss_plugin_rule_value_observable__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jss-plugin-rule-value-observable */ "./node_modules/jss-plugin-rule-value-observable/dist/jss-plugin-rule-value-observable.esm.js");
/* harmony import */ var jss_plugin_template__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jss-plugin-template */ "./node_modules/jss-plugin-template/dist/jss-plugin-template.esm.js");
/* harmony import */ var jss_plugin_global__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jss-plugin-global */ "./node_modules/jss-plugin-global/dist/jss-plugin-global.esm.js");
/* harmony import */ var jss_plugin_extend__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jss-plugin-extend */ "./node_modules/jss-plugin-extend/dist/jss-plugin-extend.esm.js");
/* harmony import */ var jss_plugin_nested__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! jss-plugin-nested */ "./node_modules/jss-plugin-nested/dist/jss-plugin-nested.esm.js");
/* harmony import */ var jss_plugin_compose__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! jss-plugin-compose */ "./node_modules/jss-plugin-compose/dist/jss-plugin-compose.esm.js");
/* harmony import */ var jss_plugin_camel_case__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! jss-plugin-camel-case */ "./node_modules/jss-plugin-camel-case/dist/jss-plugin-camel-case.esm.js");
/* harmony import */ var jss_plugin_default_unit__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! jss-plugin-default-unit */ "./node_modules/jss-plugin-default-unit/dist/jss-plugin-default-unit.esm.js");
/* harmony import */ var jss_plugin_expand__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! jss-plugin-expand */ "./node_modules/jss-plugin-expand/dist/jss-plugin-expand.esm.js");
/* harmony import */ var jss_plugin_vendor_prefixer__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! jss-plugin-vendor-prefixer */ "./node_modules/jss-plugin-vendor-prefixer/dist/jss-plugin-vendor-prefixer.esm.js");
/* harmony import */ var jss_plugin_props_sort__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! jss-plugin-props-sort */ "./node_modules/jss-plugin-props-sort/dist/jss-plugin-props-sort.esm.js");













            var index = (function (options) {
                if (options === void 0) {
                    options = {};
                }

                return {
                    plugins: [Object(jss_plugin_rule_value_function__WEBPACK_IMPORTED_MODULE_0__["default"])(), Object(jss_plugin_rule_value_observable__WEBPACK_IMPORTED_MODULE_1__["default"])(options.observable), Object(jss_plugin_template__WEBPACK_IMPORTED_MODULE_2__["default"])(), Object(jss_plugin_global__WEBPACK_IMPORTED_MODULE_3__["default"])(), Object(jss_plugin_extend__WEBPACK_IMPORTED_MODULE_4__["default"])(), Object(jss_plugin_nested__WEBPACK_IMPORTED_MODULE_5__["default"])(), Object(jss_plugin_compose__WEBPACK_IMPORTED_MODULE_6__["default"])(), Object(jss_plugin_camel_case__WEBPACK_IMPORTED_MODULE_7__["default"])(), Object(jss_plugin_default_unit__WEBPACK_IMPORTED_MODULE_8__["default"])(options.defaultUnit), Object(jss_plugin_expand__WEBPACK_IMPORTED_MODULE_9__["default"])(), Object(jss_plugin_vendor_prefixer__WEBPACK_IMPORTED_MODULE_10__["default"])(), Object(jss_plugin_props_sort__WEBPACK_IMPORTED_MODULE_11__["default"])()]
                };
            });

/* harmony default export */ __webpack_exports__["default"] = (index);


            /***/
        }),

/***/ "./node_modules/jss/dist/jss.esm.js":
/*!******************************************!*\
  !*** ./node_modules/jss/dist/jss.esm.js ***!
  \******************************************/
/*! exports provided: default, hasCSSTOMSupport, create, getDynamicStyles, toCssValue, createRule, SheetsRegistry, SheetsManager, RuleList, sheets, createGenerateId */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "hasCSSTOMSupport", function () { return hasCSSTOMSupport; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "create", function () { return create; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "getDynamicStyles", function () { return getDynamicStyles; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "toCssValue", function () { return toCssValue; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createRule", function () { return createRule; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SheetsRegistry", function () { return SheetsRegistry; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SheetsManager", function () { return SheetsManager; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RuleList", function () { return RuleList; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "sheets", function () { return sheets; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createGenerateId", function () { return createGenerateId; });
/* harmony import */ var _babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @babel/runtime/helpers/esm/extends */ "./node_modules/@babel/runtime/helpers/esm/extends.js");
/* harmony import */ var is_in_browser__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! is-in-browser */ "./node_modules/is-in-browser/dist/module.js");
/* harmony import */ var tiny_warning__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tiny-warning */ "./node_modules/tiny-warning/dist/tiny-warning.esm.js");
/* harmony import */ var _babel_runtime_helpers_esm_createClass__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @babel/runtime/helpers/esm/createClass */ "./node_modules/@babel/runtime/helpers/esm/createClass.js");
/* harmony import */ var _babel_runtime_helpers_esm_inheritsLoose__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @babel/runtime/helpers/esm/inheritsLoose */ "./node_modules/@babel/runtime/helpers/esm/inheritsLoose.js");
/* harmony import */ var _babel_runtime_helpers_esm_assertThisInitialized__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @babel/runtime/helpers/esm/assertThisInitialized */ "./node_modules/@babel/runtime/helpers/esm/assertThisInitialized.js");
/* harmony import */ var _babel_runtime_helpers_esm_objectWithoutPropertiesLoose__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @babel/runtime/helpers/esm/objectWithoutPropertiesLoose */ "./node_modules/@babel/runtime/helpers/esm/objectWithoutPropertiesLoose.js");








            var plainObjectConstrurctor = {}.constructor;
            function cloneStyle(style) {
                if (style == null || typeof style !== 'object') return style;
                if (Array.isArray(style)) return style.map(cloneStyle);
                if (style.constructor !== plainObjectConstrurctor) return style;
                var newStyle = {};

                for (var name in style) {
                    newStyle[name] = cloneStyle(style[name]);
                }

                return newStyle;
            }

            /**
             * Create a rule instance.
             */

            function createRule(name, decl, options) {
                if (name === void 0) {
                    name = 'unnamed';
                }

                var jss = options.jss;
                var declCopy = cloneStyle(decl);
                var rule = jss.plugins.onCreateRule(name, declCopy, options);
                if (rule) return rule; // It is an at-rule and it has no instance.

                if (name[0] === '@') {
                    true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] Unknown rule " + name) : undefined;
                }

                return null;
            }

            var join = function join(value, by) {
                var result = '';

                for (var i = 0; i < value.length; i++) {
                    // Remove !important from the value, it will be readded later.
                    if (value[i] === '!important') break;
                    if (result) result += by;
                    result += value[i];
                }

                return result;
            };
            /**
             * Converts array values to string.
             *
             * `margin: [['5px', '10px']]` > `margin: 5px 10px;`
             * `border: ['1px', '2px']` > `border: 1px, 2px;`
             * `margin: [['5px', '10px'], '!important']` > `margin: 5px 10px !important;`
             * `color: ['red', !important]` > `color: red !important;`
             */


            function toCssValue(value, ignoreImportant) {
                if (ignoreImportant === void 0) {
                    ignoreImportant = false;
                }

                if (!Array.isArray(value)) return value;
                var cssValue = ''; // Support space separated values via `[['5px', '10px']]`.

                if (Array.isArray(value[0])) {
                    for (var i = 0; i < value.length; i++) {
                        if (value[i] === '!important') break;
                        if (cssValue) cssValue += ', ';
                        cssValue += join(value[i], ' ');
                    }
                } else cssValue = join(value, ', '); // Add !important, because it was ignored.


                if (!ignoreImportant && value[value.length - 1] === '!important') {
                    cssValue += ' !important';
                }

                return cssValue;
            }

            /**
             * Indent a string.
             * http://jsperf.com/array-join-vs-for
             */
            function indentStr(str, indent) {
                var result = '';

                for (var index = 0; index < indent; index++) {
                    result += '  ';
                }

                return result + str;
            }
            /**
             * Converts a Rule to CSS string.
             */


            function toCss(selector, style, options) {
                if (options === void 0) {
                    options = {};
                }

                var result = '';
                if (!style) return result;
                var _options = options,
                    _options$indent = _options.indent,
                    indent = _options$indent === void 0 ? 0 : _options$indent;
                var fallbacks = style.fallbacks;
                if (selector) indent++; // Apply fallbacks first.

                if (fallbacks) {
                    // Array syntax {fallbacks: [{prop: value}]}
                    if (Array.isArray(fallbacks)) {
                        for (var index = 0; index < fallbacks.length; index++) {
                            var fallback = fallbacks[index];

                            for (var prop in fallback) {
                                var value = fallback[prop];

                                if (value != null) {
                                    if (result) result += '\n';
                                    result += "" + indentStr(prop + ": " + toCssValue(value) + ";", indent);
                                }
                            }
                        }
                    } else {
                        // Object syntax {fallbacks: {prop: value}}
                        for (var _prop in fallbacks) {
                            var _value = fallbacks[_prop];

                            if (_value != null) {
                                if (result) result += '\n';
                                result += "" + indentStr(_prop + ": " + toCssValue(_value) + ";", indent);
                            }
                        }
                    }
                }

                for (var _prop2 in style) {
                    var _value2 = style[_prop2];

                    if (_value2 != null && _prop2 !== 'fallbacks') {
                        if (result) result += '\n';
                        result += "" + indentStr(_prop2 + ": " + toCssValue(_value2) + ";", indent);
                    }
                } // Allow empty style in this case, because properties will be added dynamically.


                if (!result && !options.allowEmpty) return result; // When rule is being stringified before selector was defined.

                if (!selector) return result;
                indent--;
                if (result) result = "\n" + result + "\n";
                return indentStr(selector + " {" + result, indent) + indentStr('}', indent);
            }

            var escapeRegex = /([[\].#*$><+~=|^:(),"'`\s])/g;
            var nativeEscape = typeof CSS !== 'undefined' && CSS.escape;
            var escape = (function (str) {
                return nativeEscape ? nativeEscape(str) : str.replace(escapeRegex, '\\$1');
            });

            var BaseStyleRule =
                /*#__PURE__*/
                function () {
                    function BaseStyleRule(key, style, options) {
                        this.type = 'style';
                        this.key = void 0;
                        this.isProcessed = false;
                        this.style = void 0;
                        this.renderer = void 0;
                        this.renderable = void 0;
                        this.options = void 0;
                        var sheet = options.sheet,
                            Renderer = options.Renderer;
                        this.key = key;
                        this.options = options;
                        this.style = style;
                        if (sheet) this.renderer = sheet.renderer; else if (Renderer) this.renderer = new Renderer();
                    }
                    /**
                     * Get or set a style property.
                     */


                    var _proto = BaseStyleRule.prototype;

                    _proto.prop = function prop(name, value, options) {
                        // It's a getter.
                        if (value === undefined) return this.style[name]; // Don't do anything if the value has not changed.

                        var force = options ? options.force : false;
                        if (!force && this.style[name] === value) return this;
                        var newValue = value;

                        if (!options || options.process !== false) {
                            newValue = this.options.jss.plugins.onChangeValue(value, name, this);
                        }

                        var isEmpty = newValue == null || newValue === false;
                        var isDefined = name in this.style; // Value is empty and wasn't defined before.

                        if (isEmpty && !isDefined && !force) return this; // We are going to remove this value.

                        var remove = isEmpty && isDefined;
                        if (remove) delete this.style[name]; else this.style[name] = newValue; // Renderable is defined if StyleSheet option `link` is true.

                        if (this.renderable && this.renderer) {
                            if (remove) this.renderer.removeProperty(this.renderable, name); else this.renderer.setProperty(this.renderable, name, newValue);
                            return this;
                        }

                        var sheet = this.options.sheet;

                        if (sheet && sheet.attached) {
                            true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, '[JSS] Rule is not linked. Missing sheet option "link: true".') : undefined;
                        }

                        return this;
                    };

                    return BaseStyleRule;
                }();
            var StyleRule =
                /*#__PURE__*/
                function (_BaseStyleRule) {
                    Object(_babel_runtime_helpers_esm_inheritsLoose__WEBPACK_IMPORTED_MODULE_4__["default"])(StyleRule, _BaseStyleRule);

                    function StyleRule(key, style, options) {
                        var _this;

                        _this = _BaseStyleRule.call(this, key, style, options) || this;
                        _this.selectorText = void 0;
                        _this.id = void 0;
                        _this.renderable = void 0;
                        var selector = options.selector,
                            scoped = options.scoped,
                            sheet = options.sheet,
                            generateId = options.generateId;

                        if (selector) {
                            _this.selectorText = selector;
                        } else if (scoped !== false) {
                            _this.id = generateId(Object(_babel_runtime_helpers_esm_assertThisInitialized__WEBPACK_IMPORTED_MODULE_5__["default"])(Object(_babel_runtime_helpers_esm_assertThisInitialized__WEBPACK_IMPORTED_MODULE_5__["default"])(_this)), sheet);
                            _this.selectorText = "." + escape(_this.id);
                        }

                        return _this;
                    }
                    /**
                     * Set selector string.
                     * Attention: use this with caution. Most browsers didn't implement
                     * selectorText setter, so this may result in rerendering of entire Style Sheet.
                     */


                    var _proto2 = StyleRule.prototype;

                    /**
                     * Apply rule to an element inline.
                     */
                    _proto2.applyTo = function applyTo(renderable) {
                        var renderer = this.renderer;

                        if (renderer) {
                            var json = this.toJSON();

                            for (var prop in json) {
                                renderer.setProperty(renderable, prop, json[prop]);
                            }
                        }

                        return this;
                    }
                        /**
                         * Returns JSON representation of the rule.
                         * Fallbacks are not supported.
                         * Useful for inline styles.
                         */
                        ;

                    _proto2.toJSON = function toJSON() {
                        var json = {};

                        for (var prop in this.style) {
                            var value = this.style[prop];
                            if (typeof value !== 'object') json[prop] = value; else if (Array.isArray(value)) json[prop] = toCssValue(value);
                        }

                        return json;
                    }
                        /**
                         * Generates a CSS string.
                         */
                        ;

                    _proto2.toString = function toString(options) {
                        var sheet = this.options.sheet;
                        var link = sheet ? sheet.options.link : false;
                        var opts = link ? Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            allowEmpty: true
                        }) : options;
                        return toCss(this.selectorText, this.style, opts);
                    };

                    Object(_babel_runtime_helpers_esm_createClass__WEBPACK_IMPORTED_MODULE_3__["default"])(StyleRule, [{
                        key: "selector",
                        set: function set(selector) {
                            if (selector === this.selectorText) return;
                            this.selectorText = selector;
                            var renderer = this.renderer,
                                renderable = this.renderable;
                            if (!renderable || !renderer) return;
                            var hasChanged = renderer.setSelector(renderable, selector); // If selector setter is not implemented, rerender the rule.

                            if (!hasChanged) {
                                renderer.replaceRule(renderable, this);
                            }
                        }
                        /**
                         * Get selector string.
                         */
                        ,
                        get: function get() {
                            return this.selectorText;
                        }
                    }]);

                    return StyleRule;
                }(BaseStyleRule);
            var pluginStyleRule = {
                onCreateRule: function onCreateRule(name, style, options) {
                    if (name[0] === '@' || options.parent && options.parent.type === 'keyframes') {
                        return null;
                    }

                    return new StyleRule(name, style, options);
                }
            };

            var defaultToStringOptions = {
                indent: 1,
                children: true
            };
            var atRegExp = /@([\w-]+)/;
            /**
             * Conditional rule for @media, @supports
             */

            var ConditionalRule =
                /*#__PURE__*/
                function () {
                    function ConditionalRule(key, styles, options) {
                        this.type = 'conditional';
                        this.at = void 0;
                        this.key = void 0;
                        this.rules = void 0;
                        this.options = void 0;
                        this.isProcessed = false;
                        this.renderable = void 0;
                        this.key = key;
                        var atMatch = key.match(atRegExp);
                        this.at = atMatch ? atMatch[1] : 'unknown';
                        this.options = options;
                        this.rules = new RuleList(Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            parent: this
                        }));

                        for (var name in styles) {
                            this.rules.add(name, styles[name]);
                        }

                        this.rules.process();
                    }
                    /**
                     * Get a rule.
                     */


                    var _proto = ConditionalRule.prototype;

                    _proto.getRule = function getRule(name) {
                        return this.rules.get(name);
                    }
                        /**
                         * Get index of a rule.
                         */
                        ;

                    _proto.indexOf = function indexOf(rule) {
                        return this.rules.indexOf(rule);
                    }
                        /**
                         * Create and register rule, run plugins.
                         */
                        ;

                    _proto.addRule = function addRule(name, style, options) {
                        var rule = this.rules.add(name, style, options);
                        if (!rule) return null;
                        this.options.jss.plugins.onProcessRule(rule);
                        return rule;
                    }
                        /**
                         * Generates a CSS string.
                         */
                        ;

                    _proto.toString = function toString(options) {
                        if (options === void 0) {
                            options = defaultToStringOptions;
                        }

                        if (options.indent == null) options.indent = defaultToStringOptions.indent;
                        if (options.children == null) options.children = defaultToStringOptions.children;

                        if (options.children === false) {
                            return this.key + " {}";
                        }

                        var children = this.rules.toString(options);
                        return children ? this.key + " {\n" + children + "\n}" : '';
                    };

                    return ConditionalRule;
                }();
            var keyRegExp = /@media|@supports\s+/;
            var pluginConditionalRule = {
                onCreateRule: function onCreateRule(key, styles, options) {
                    return keyRegExp.test(key) ? new ConditionalRule(key, styles, options) : null;
                }
            };

            var defaultToStringOptions$1 = {
                indent: 1,
                children: true
            };
            var nameRegExp = /@keyframes\s+([\w-]+)/;
            /**
             * Rule for @keyframes
             */

            var KeyframesRule =
                /*#__PURE__*/
                function () {
                    function KeyframesRule(key, frames, options) {
                        this.type = 'keyframes';
                        this.at = '@keyframes';
                        this.key = void 0;
                        this.name = void 0;
                        this.id = void 0;
                        this.rules = void 0;
                        this.options = void 0;
                        this.isProcessed = false;
                        this.renderable = void 0;
                        var nameMatch = key.match(nameRegExp);

                        if (nameMatch && nameMatch[1]) {
                            this.name = nameMatch[1];
                        } else {
                            this.name = 'noname';
                            true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] Bad keyframes name " + key) : undefined;
                        }

                        this.key = this.type + "-" + this.name;
                        this.options = options;
                        var scoped = options.scoped,
                            sheet = options.sheet,
                            generateId = options.generateId;
                        this.id = scoped === false ? this.name : escape(generateId(this, sheet));
                        this.rules = new RuleList(Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            parent: this
                        }));

                        for (var name in frames) {
                            this.rules.add(name, frames[name], Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                                parent: this
                            }));
                        }

                        this.rules.process();
                    }
                    /**
                     * Generates a CSS string.
                     */


                    var _proto = KeyframesRule.prototype;

                    _proto.toString = function toString(options) {
                        if (options === void 0) {
                            options = defaultToStringOptions$1;
                        }

                        if (options.indent == null) options.indent = defaultToStringOptions$1.indent;
                        if (options.children == null) options.children = defaultToStringOptions$1.children;

                        if (options.children === false) {
                            return this.at + " " + this.id + " {}";
                        }

                        var children = this.rules.toString(options);
                        if (children) children = "\n" + children + "\n";
                        return this.at + " " + this.id + " {" + children + "}";
                    };

                    return KeyframesRule;
                }();
            var keyRegExp$1 = /@keyframes\s+/;
            var refRegExp = /\$([\w-]+)/g;

            var findReferencedKeyframe = function findReferencedKeyframe(val, keyframes) {
                if (typeof val === 'string') {
                    return val.replace(refRegExp, function (match, name) {
                        if (name in keyframes) {
                            return keyframes[name];
                        }

                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] Referenced keyframes rule \"" + name + "\" is not defined.") : undefined;
                        return match;
                    });
                }

                return val;
            };
            /**
             * Replace the reference for a animation name.
             */


            var replaceRef = function replaceRef(style, prop, keyframes) {
                var value = style[prop];
                var refKeyframe = findReferencedKeyframe(value, keyframes);

                if (refKeyframe !== value) {
                    style[prop] = refKeyframe;
                }
            };

            var plugin = {
                onCreateRule: function onCreateRule(key, frames, options) {
                    return typeof key === 'string' && keyRegExp$1.test(key) ? new KeyframesRule(key, frames, options) : null;
                },
                // Animation name ref replacer.
                onProcessStyle: function onProcessStyle(style, rule, sheet) {
                    if (rule.type !== 'style' || !sheet) return style;
                    if ('animation-name' in style) replaceRef(style, 'animation-name', sheet.keyframes);
                    if ('animation' in style) replaceRef(style, 'animation', sheet.keyframes);
                    return style;
                },
                onChangeValue: function onChangeValue(val, prop, rule) {
                    var sheet = rule.options.sheet;

                    if (!sheet) {
                        return val;
                    }

                    switch (prop) {
                        case 'animation':
                            return findReferencedKeyframe(val, sheet.keyframes);

                        case 'animation-name':
                            return findReferencedKeyframe(val, sheet.keyframes);

                        default:
                            return val;
                    }
                }
            };

            var KeyframeRule =
                /*#__PURE__*/
                function (_BaseStyleRule) {
                    Object(_babel_runtime_helpers_esm_inheritsLoose__WEBPACK_IMPORTED_MODULE_4__["default"])(KeyframeRule, _BaseStyleRule);

                    function KeyframeRule() {
                        var _this;

                        for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
                            args[_key] = arguments[_key];
                        }

                        _this = _BaseStyleRule.call.apply(_BaseStyleRule, [this].concat(args)) || this;
                        _this.renderable = void 0;
                        return _this;
                    }

                    var _proto = KeyframeRule.prototype;

                    /**
                     * Generates a CSS string.
                     */
                    _proto.toString = function toString(options) {
                        var sheet = this.options.sheet;
                        var link = sheet ? sheet.options.link : false;
                        var opts = link ? Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            allowEmpty: true
                        }) : options;
                        return toCss(this.key, this.style, opts);
                    };

                    return KeyframeRule;
                }(BaseStyleRule);
            var pluginKeyframeRule = {
                onCreateRule: function onCreateRule(key, style, options) {
                    if (options.parent && options.parent.type === 'keyframes') {
                        return new KeyframeRule(key, style, options);
                    }

                    return null;
                }
            };

            var FontFaceRule =
                /*#__PURE__*/
                function () {
                    function FontFaceRule(key, style, options) {
                        this.type = 'font-face';
                        this.at = '@font-face';
                        this.key = void 0;
                        this.style = void 0;
                        this.options = void 0;
                        this.isProcessed = false;
                        this.renderable = void 0;
                        this.key = key;
                        this.style = style;
                        this.options = options;
                    }
                    /**
                     * Generates a CSS string.
                     */


                    var _proto = FontFaceRule.prototype;

                    _proto.toString = function toString(options) {
                        if (Array.isArray(this.style)) {
                            var str = '';

                            for (var index = 0; index < this.style.length; index++) {
                                str += toCss(this.key, this.style[index]);
                                if (this.style[index + 1]) str += '\n';
                            }

                            return str;
                        }

                        return toCss(this.key, this.style, options);
                    };

                    return FontFaceRule;
                }();
            var pluginFontFaceRule = {
                onCreateRule: function onCreateRule(key, style, options) {
                    return key === '@font-face' ? new FontFaceRule(key, style, options) : null;
                }
            };

            var ViewportRule =
                /*#__PURE__*/
                function () {
                    function ViewportRule(key, style, options) {
                        this.type = 'viewport';
                        this.at = '@viewport';
                        this.key = void 0;
                        this.style = void 0;
                        this.options = void 0;
                        this.isProcessed = false;
                        this.renderable = void 0;
                        this.key = key;
                        this.style = style;
                        this.options = options;
                    }
                    /**
                     * Generates a CSS string.
                     */


                    var _proto = ViewportRule.prototype;

                    _proto.toString = function toString(options) {
                        return toCss(this.key, this.style, options);
                    };

                    return ViewportRule;
                }();
            var pluginViewportRule = {
                onCreateRule: function onCreateRule(key, style, options) {
                    return key === '@viewport' || key === '@-ms-viewport' ? new ViewportRule(key, style, options) : null;
                }
            };

            var SimpleRule =
                /*#__PURE__*/
                function () {
                    function SimpleRule(key, value, options) {
                        this.type = 'simple';
                        this.key = void 0;
                        this.value = void 0;
                        this.options = void 0;
                        this.isProcessed = false;
                        this.renderable = void 0;
                        this.key = key;
                        this.value = value;
                        this.options = options;
                    }
                    /**
                     * Generates a CSS string.
                     */
                    // eslint-disable-next-line no-unused-vars


                    var _proto = SimpleRule.prototype;

                    _proto.toString = function toString(options) {
                        if (Array.isArray(this.value)) {
                            var str = '';

                            for (var index = 0; index < this.value.length; index++) {
                                str += this.key + " " + this.value[index] + ";";
                                if (this.value[index + 1]) str += '\n';
                            }

                            return str;
                        }

                        return this.key + " " + this.value + ";";
                    };

                    return SimpleRule;
                }();
            var keysMap = {
                '@charset': true,
                '@import': true,
                '@namespace': true
            };
            var pluginSimpleRule = {
                onCreateRule: function onCreateRule(key, value, options) {
                    return key in keysMap ? new SimpleRule(key, value, options) : null;
                }
            };

            var plugins = [pluginStyleRule, pluginConditionalRule, plugin, pluginKeyframeRule, pluginFontFaceRule, pluginViewportRule, pluginSimpleRule];

            var defaultUpdateOptions = {
                process: true
            };
            var forceUpdateOptions = {
                force: true,
                process: true
                /**
                 * Contains rules objects and allows adding/removing etc.
                 * Is used for e.g. by `StyleSheet` or `ConditionalRule`.
                 */

            };

            var RuleList =
                /*#__PURE__*/
                function () {
                    // Rules registry for access by .get() method.
                    // It contains the same rule registered by name and by selector.
                    // Original styles object.
                    // Used to ensure correct rules order.
                    function RuleList(options) {
                        this.map = {};
                        this.raw = {};
                        this.index = [];
                        this.options = void 0;
                        this.classes = void 0;
                        this.keyframes = void 0;
                        this.options = options;
                        this.classes = options.classes;
                        this.keyframes = options.keyframes;
                    }
                    /**
                     * Create and register rule.
                     *
                     * Will not render after Style Sheet was rendered the first time.
                     */


                    var _proto = RuleList.prototype;

                    _proto.add = function add(key, decl, ruleOptions) {
                        var _this$options = this.options,
                            parent = _this$options.parent,
                            sheet = _this$options.sheet,
                            jss = _this$options.jss,
                            Renderer = _this$options.Renderer,
                            generateId = _this$options.generateId,
                            scoped = _this$options.scoped;

                        var options = Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({
                            classes: this.classes,
                            parent: parent,
                            sheet: sheet,
                            jss: jss,
                            Renderer: Renderer,
                            generateId: generateId,
                            scoped: scoped
                        }, ruleOptions); // We need to save the original decl before creating the rule
                        // because cache plugin needs to use it as a key to return a cached rule.


                        this.raw[key] = decl;

                        if (key in this.classes) {
                            // For e.g. rules inside of @media container
                            options.selector = "." + escape(this.classes[key]);
                        }

                        var rule = createRule(key, decl, options);
                        if (!rule) return null;
                        this.register(rule);
                        var index = options.index === undefined ? this.index.length : options.index;
                        this.index.splice(index, 0, rule);
                        return rule;
                    }
                        /**
                         * Get a rule.
                         */
                        ;

                    _proto.get = function get(name) {
                        return this.map[name];
                    }
                        /**
                         * Delete a rule.
                         */
                        ;

                    _proto.remove = function remove(rule) {
                        this.unregister(rule);
                        delete this.raw[rule.key];
                        this.index.splice(this.indexOf(rule), 1);
                    }
                        /**
                         * Get index of a rule.
                         */
                        ;

                    _proto.indexOf = function indexOf(rule) {
                        return this.index.indexOf(rule);
                    }
                        /**
                         * Run `onProcessRule()` plugins on every rule.
                         */
                        ;

                    _proto.process = function process() {
                        var plugins$$1 = this.options.jss.plugins; // We need to clone array because if we modify the index somewhere else during a loop
                        // we end up with very hard-to-track-down side effects.

                        this.index.slice(0).forEach(plugins$$1.onProcessRule, plugins$$1);
                    }
                        /**
                         * Register a rule in `.map` and `.classes` maps.
                         */
                        ;

                    _proto.register = function register(rule) {
                        this.map[rule.key] = rule;

                        if (rule instanceof StyleRule) {
                            this.map[rule.selector] = rule;
                            if (rule.id) this.classes[rule.key] = rule.id;
                        } else if (rule instanceof KeyframesRule && this.keyframes) {
                            this.keyframes[rule.name] = rule.id;
                        }
                    }
                        /**
                         * Unregister a rule.
                         */
                        ;

                    _proto.unregister = function unregister(rule) {
                        delete this.map[rule.key];

                        if (rule instanceof StyleRule) {
                            delete this.map[rule.selector];
                            delete this.classes[rule.key];
                        } else if (rule instanceof KeyframesRule) {
                            delete this.keyframes[rule.name];
                        }
                    }
                        /**
                         * Update the function values with a new data.
                         */
                        ;

                    _proto.update = function update() {
                        var name;
                        var data;
                        var options;

                        if (typeof (arguments.length <= 0 ? undefined : arguments[0]) === 'string') {
                            name = arguments.length <= 0 ? undefined : arguments[0]; // $FlowFixMe

                            data = arguments.length <= 1 ? undefined : arguments[1]; // $FlowFixMe

                            options = arguments.length <= 2 ? undefined : arguments[2];
                        } else {
                            data = arguments.length <= 0 ? undefined : arguments[0]; // $FlowFixMe

                            options = arguments.length <= 1 ? undefined : arguments[1];
                            name = null;
                        }

                        if (name) {
                            this.onUpdate(data, this.get(name), options);
                        } else {
                            for (var index = 0; index < this.index.length; index++) {
                                this.onUpdate(data, this.index[index], options);
                            }
                        }
                    }
                        /**
                         * Execute plugins, update rule props.
                         */
                        ;

                    _proto.onUpdate = function onUpdate(data, rule, options) {
                        if (options === void 0) {
                            options = defaultUpdateOptions;
                        }

                        var _this$options2 = this.options,
                            plugins$$1 = _this$options2.jss.plugins,
                            sheet = _this$options2.sheet; // It is a rules container like for e.g. ConditionalRule.

                        if (rule.rules instanceof RuleList) {
                            rule.rules.update(data, options);
                            return;
                        }

                        var styleRule = rule;
                        var style = styleRule.style;
                        plugins$$1.onUpdate(data, rule, sheet, options); // We rely on a new `style` ref in case it was mutated during onUpdate hook.

                        if (options.process && style && style !== styleRule.style) {
                            // We need to run the plugins in case new `style` relies on syntax plugins.
                            plugins$$1.onProcessStyle(styleRule.style, styleRule, sheet); // Update and add props.

                            for (var prop in styleRule.style) {
                                var nextValue = styleRule.style[prop];
                                var prevValue = style[prop]; // We need to use `force: true` because `rule.style` has been updated during onUpdate hook, so `rule.prop()` will not update the CSSOM rule.
                                // We do this comparison to avoid unneeded `rule.prop()` calls, since we have the old `style` object here.

                                if (nextValue !== prevValue) {
                                    styleRule.prop(prop, nextValue, forceUpdateOptions);
                                }
                            } // Remove props.


                            for (var _prop in style) {
                                var _nextValue = styleRule.style[_prop];
                                var _prevValue = style[_prop]; // We need to use `force: true` because `rule.style` has been updated during onUpdate hook, so `rule.prop()` will not update the CSSOM rule.
                                // We do this comparison to avoid unneeded `rule.prop()` calls, since we have the old `style` object here.

                                if (_nextValue == null && _nextValue !== _prevValue) {
                                    styleRule.prop(_prop, null, forceUpdateOptions);
                                }
                            }
                        }
                    }
                        /**
                         * Convert rules to a CSS string.
                         */
                        ;

                    _proto.toString = function toString(options) {
                        var str = '';
                        var sheet = this.options.sheet;
                        var link = sheet ? sheet.options.link : false;

                        for (var index = 0; index < this.index.length; index++) {
                            var rule = this.index[index];
                            var css = rule.toString(options); // No need to render an empty rule.

                            if (!css && !link) continue;
                            if (str) str += '\n';
                            str += css;
                        }

                        return str;
                    };

                    return RuleList;
                }();

            var StyleSheet =
                /*#__PURE__*/
                function () {
                    function StyleSheet(styles, options) {
                        this.options = void 0;
                        this.deployed = void 0;
                        this.attached = void 0;
                        this.rules = void 0;
                        this.renderer = void 0;
                        this.classes = void 0;
                        this.keyframes = void 0;
                        this.queue = void 0;
                        this.attached = false;
                        this.deployed = false;
                        this.classes = {};
                        this.keyframes = {};
                        this.options = Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            sheet: this,
                            parent: this,
                            classes: this.classes,
                            keyframes: this.keyframes
                        });

                        if (options.Renderer) {
                            this.renderer = new options.Renderer(this);
                        }

                        this.rules = new RuleList(this.options);

                        for (var name in styles) {
                            this.rules.add(name, styles[name]);
                        }

                        this.rules.process();
                    }
                    /**
                     * Attach renderable to the render tree.
                     */


                    var _proto = StyleSheet.prototype;

                    _proto.attach = function attach() {
                        if (this.attached) return this;
                        if (this.renderer) this.renderer.attach();
                        this.attached = true; // Order is important, because we can't use insertRule API if style element is not attached.

                        if (!this.deployed) this.deploy();
                        return this;
                    }
                        /**
                         * Remove renderable from render tree.
                         */
                        ;

                    _proto.detach = function detach() {
                        if (!this.attached) return this;
                        if (this.renderer) this.renderer.detach();
                        this.attached = false;
                        return this;
                    }
                        /**
                         * Add a rule to the current stylesheet.
                         * Will insert a rule also after the stylesheet has been rendered first time.
                         */
                        ;

                    _proto.addRule = function addRule(name, decl, options) {
                        var queue = this.queue; // Plugins can create rules.
                        // In order to preserve the right order, we need to queue all `.addRule` calls,
                        // which happen after the first `rules.add()` call.

                        if (this.attached && !queue) this.queue = [];
                        var rule = this.rules.add(name, decl, options);
                        if (!rule) return null;
                        this.options.jss.plugins.onProcessRule(rule);

                        if (this.attached) {
                            if (!this.deployed) return rule; // Don't insert rule directly if there is no stringified version yet.
                            // It will be inserted all together when .attach is called.

                            if (queue) queue.push(rule); else {
                                this.insertRule(rule);

                                if (this.queue) {
                                    this.queue.forEach(this.insertRule, this);
                                    this.queue = undefined;
                                }
                            }
                            return rule;
                        } // We can't add rules to a detached style node.
                        // We will redeploy the sheet once user will attach it.


                        this.deployed = false;
                        return rule;
                    }
                        /**
                         * Insert rule into the StyleSheet
                         */
                        ;

                    _proto.insertRule = function insertRule(rule) {
                        if (this.renderer) {
                            this.renderer.insertRule(rule);
                        }
                    }
                        /**
                         * Create and add rules.
                         * Will render also after Style Sheet was rendered the first time.
                         */
                        ;

                    _proto.addRules = function addRules(styles, options) {
                        var added = [];

                        for (var name in styles) {
                            var rule = this.addRule(name, styles[name], options);
                            if (rule) added.push(rule);
                        }

                        return added;
                    }
                        /**
                         * Get a rule by name.
                         */
                        ;

                    _proto.getRule = function getRule(name) {
                        return this.rules.get(name);
                    }
                        /**
                         * Delete a rule by name.
                         * Returns `true`: if rule has been deleted from the DOM.
                         */
                        ;

                    _proto.deleteRule = function deleteRule(name) {
                        var rule = this.rules.get(name);
                        if (!rule) return false;
                        this.rules.remove(rule);

                        if (this.attached && rule.renderable && this.renderer) {
                            return this.renderer.deleteRule(rule.renderable);
                        }

                        return true;
                    }
                        /**
                         * Get index of a rule.
                         */
                        ;

                    _proto.indexOf = function indexOf(rule) {
                        return this.rules.indexOf(rule);
                    }
                        /**
                         * Deploy pure CSS string to a renderable.
                         */
                        ;

                    _proto.deploy = function deploy() {
                        if (this.renderer) this.renderer.deploy();
                        this.deployed = true;
                        return this;
                    }
                        /**
                         * Update the function values with a new data.
                         */
                        ;

                    _proto.update = function update() {
                        var _this$rules;

                        (_this$rules = this.rules).update.apply(_this$rules, arguments);

                        return this;
                    }
                        /**
                         * Convert rules to a CSS string.
                         */
                        ;

                    _proto.toString = function toString(options) {
                        return this.rules.toString(options);
                    };

                    return StyleSheet;
                }();

            var PluginsRegistry =
                /*#__PURE__*/
                function () {
                    function PluginsRegistry() {
                        this.plugins = {
                            internal: [],
                            external: []
                        };
                        this.registry = void 0;
                    }

                    var _proto = PluginsRegistry.prototype;

                    /**
                     * Call `onCreateRule` hooks and return an object if returned by a hook.
                     */
                    _proto.onCreateRule = function onCreateRule(name, decl, options) {
                        for (var i = 0; i < this.registry.onCreateRule.length; i++) {
                            var rule = this.registry.onCreateRule[i](name, decl, options);
                            if (rule) return rule;
                        }

                        return null;
                    }
                        /**
                         * Call `onProcessRule` hooks.
                         */
                        ;

                    _proto.onProcessRule = function onProcessRule(rule) {
                        if (rule.isProcessed) return;
                        var sheet = rule.options.sheet;

                        for (var i = 0; i < this.registry.onProcessRule.length; i++) {
                            this.registry.onProcessRule[i](rule, sheet);
                        }

                        if (rule.style) this.onProcessStyle(rule.style, rule, sheet);
                        rule.isProcessed = true;
                    }
                        /**
                         * Call `onProcessStyle` hooks.
                         */
                        ;

                    _proto.onProcessStyle = function onProcessStyle(style, rule, sheet) {
                        for (var i = 0; i < this.registry.onProcessStyle.length; i++) {
                            // $FlowFixMe
                            rule.style = this.registry.onProcessStyle[i](rule.style, rule, sheet);
                        }
                    }
                        /**
                         * Call `onProcessSheet` hooks.
                         */
                        ;

                    _proto.onProcessSheet = function onProcessSheet(sheet) {
                        for (var i = 0; i < this.registry.onProcessSheet.length; i++) {
                            this.registry.onProcessSheet[i](sheet);
                        }
                    }
                        /**
                         * Call `onUpdate` hooks.
                         */
                        ;

                    _proto.onUpdate = function onUpdate(data, rule, sheet, options) {
                        for (var i = 0; i < this.registry.onUpdate.length; i++) {
                            this.registry.onUpdate[i](data, rule, sheet, options);
                        }
                    }
                        /**
                         * Call `onChangeValue` hooks.
                         */
                        ;

                    _proto.onChangeValue = function onChangeValue(value, prop, rule) {
                        var processedValue = value;

                        for (var i = 0; i < this.registry.onChangeValue.length; i++) {
                            processedValue = this.registry.onChangeValue[i](processedValue, prop, rule);
                        }

                        return processedValue;
                    }
                        /**
                         * Register a plugin.
                         */
                        ;

                    _proto.use = function use(newPlugin, options) {
                        if (options === void 0) {
                            options = {
                                queue: 'external'
                            };
                        }

                        var plugins = this.plugins[options.queue]; // Avoids applying same plugin twice, at least based on ref.

                        if (plugins.indexOf(newPlugin) !== -1) {
                            return;
                        }

                        plugins.push(newPlugin);
                        this.registry = [].concat(this.plugins.external, this.plugins.internal).reduce(function (registry, plugin) {
                            for (var name in plugin) {
                                if (name in registry) {
                                    registry[name].push(plugin[name]);
                                } else {
                                    true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] Unknown hook \"" + name + "\".") : undefined;
                                }
                            }

                            return registry;
                        }, {
                            onCreateRule: [],
                            onProcessRule: [],
                            onProcessStyle: [],
                            onProcessSheet: [],
                            onChangeValue: [],
                            onUpdate: []
                        });
                    };

                    return PluginsRegistry;
                }();

            /**
             * Sheets registry to access them all at one place.
             */
            var SheetsRegistry =
                /*#__PURE__*/
                function () {
                    function SheetsRegistry() {
                        this.registry = [];
                    }

                    var _proto = SheetsRegistry.prototype;

                    /**
                     * Register a Style Sheet.
                     */
                    _proto.add = function add(sheet) {
                        var registry = this.registry;
                        var index = sheet.options.index;
                        if (registry.indexOf(sheet) !== -1) return;

                        if (registry.length === 0 || index >= this.index) {
                            registry.push(sheet);
                            return;
                        } // Find a position.


                        for (var i = 0; i < registry.length; i++) {
                            if (registry[i].options.index > index) {
                                registry.splice(i, 0, sheet);
                                return;
                            }
                        }
                    }
                        /**
                         * Reset the registry.
                         */
                        ;

                    _proto.reset = function reset() {
                        this.registry = [];
                    }
                        /**
                         * Remove a Style Sheet.
                         */
                        ;

                    _proto.remove = function remove(sheet) {
                        var index = this.registry.indexOf(sheet);
                        this.registry.splice(index, 1);
                    }
                        /**
                         * Convert all attached sheets to a CSS string.
                         */
                        ;

                    _proto.toString = function toString(_temp) {
                        var _ref = _temp === void 0 ? {} : _temp,
                            attached = _ref.attached,
                            options = Object(_babel_runtime_helpers_esm_objectWithoutPropertiesLoose__WEBPACK_IMPORTED_MODULE_6__["default"])(_ref, ["attached"]);

                        var css = '';

                        for (var i = 0; i < this.registry.length; i++) {
                            var sheet = this.registry[i];

                            if (attached != null && sheet.attached !== attached) {
                                continue;
                            }

                            if (css) css += '\n';
                            css += sheet.toString(options);
                        }

                        return css;
                    };

                    Object(_babel_runtime_helpers_esm_createClass__WEBPACK_IMPORTED_MODULE_3__["default"])(SheetsRegistry, [{
                        key: "index",

                        /**
                         * Current highest index number.
                         */
                        get: function get() {
                            return this.registry.length === 0 ? 0 : this.registry[this.registry.length - 1].options.index;
                        }
                    }]);

                    return SheetsRegistry;
                }();

            /**
             * This is a global sheets registry. Only DomRenderer will add sheets to it.
             * On the server one should use an own SheetsRegistry instance and add the
             * sheets to it, because you need to make sure to create a new registry for
             * each request in order to not leak sheets across requests.
             */

            var sheets = new SheetsRegistry();

            /* eslint-disable */
            // https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
            var globalThis = typeof window != 'undefined' && window.Math == Math ? window : typeof self != 'undefined' && self.Math == Math ? self : Function('return this')();

            var ns = '2f1acc6c3a606b082e5eef5e54414ffb';
            if (globalThis[ns] == null) globalThis[ns] = 0; // Bundle may contain multiple JSS versions at the same time. In order to identify
            // the current version with just one short number and use it for classes generation
            // we use a counter. Also it is more accurate, because user can manually reevaluate
            // the module.

            var moduleId = globalThis[ns]++;

            var maxRules = 1e10;

            /**
             * Returns a function which generates unique class names based on counters.
             * When new generator function is created, rule counter is reseted.
             * We need to reset the rule counter for SSR for each request.
             */
            var createGenerateId = function createGenerateId(options) {
                if (options === void 0) {
                    options = {};
                }

                var ruleCounter = 0;
                return function (rule, sheet) {
                    ruleCounter += 1;

                    if (ruleCounter > maxRules) {
                        true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] You might have a memory leak. Rule counter is at " + ruleCounter + ".") : undefined;
                    }

                    var jssId = '';
                    var prefix = '';

                    if (sheet) {
                        if (sheet.options.classNamePrefix) {
                            prefix = sheet.options.classNamePrefix;
                        }

                        if (sheet.options.jss.id != null) {
                            jssId = String(sheet.options.jss.id);
                        }
                    }

                    if (options.minify) {
                        // Using "c" because a number can't be the first char in a class name.
                        return "" + (prefix || 'c') + moduleId + jssId + ruleCounter;
                    }

                    return prefix + rule.key + "-" + moduleId + (jssId ? "-" + jssId : '') + "-" + ruleCounter;
                };
            };

            /**
             * Cache the value from the first time a function is called.
             */
            var memoize = function memoize(fn) {
                var value;
                return function () {
                    if (!value) value = fn();
                    return value;
                };
            };
            /**
             * Get a style property value.
             */


            function getPropertyValue(cssRule, prop) {
                try {
                    // Support CSSTOM.
                    if (cssRule.attributeStyleMap) {
                        return cssRule.attributeStyleMap.get(prop);
                    }

                    return cssRule.style.getPropertyValue(prop);
                } catch (err) {
                    // IE may throw if property is unknown.
                    return '';
                }
            }
            /**
             * Set a style property.
             */


            function setProperty(cssRule, prop, value) {
                try {
                    var cssValue = value;

                    if (Array.isArray(value)) {
                        cssValue = toCssValue(value, true);

                        if (value[value.length - 1] === '!important') {
                            cssRule.style.setProperty(prop, cssValue, 'important');
                            return true;
                        }
                    } // Support CSSTOM.


                    if (cssRule.attributeStyleMap) {
                        cssRule.attributeStyleMap.set(prop, cssValue);
                    } else {
                        cssRule.style.setProperty(prop, cssValue);
                    }
                } catch (err) {
                    // IE may throw if property is unknown.
                    return false;
                }

                return true;
            }
            /**
             * Remove a style property.
             */


            function removeProperty(cssRule, prop) {
                try {
                    // Support CSSTOM.
                    if (cssRule.attributeStyleMap) {
                        cssRule.attributeStyleMap.delete(prop);
                    } else {
                        cssRule.style.removeProperty(prop);
                    }
                } catch (err) {
                    true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] DOMException \"" + err.message + "\" was thrown. Tried to remove property \"" + prop + "\".") : undefined;
                }
            }
            /**
             * Set the selector.
             */


            function setSelector(cssRule, selectorText) {
                cssRule.selectorText = selectorText; // Return false if setter was not successful.
                // Currently works in chrome only.

                return cssRule.selectorText === selectorText;
            }
            /**
             * Gets the `head` element upon the first call and caches it.
             * We assume it can't be null.
             */


            var getHead = memoize(function () {
                return document.querySelector('head');
            });
            /**
             * Find attached sheet with an index higher than the passed one.
             */

            function findHigherSheet(registry, options) {
                for (var i = 0; i < registry.length; i++) {
                    var sheet = registry[i];

                    if (sheet.attached && sheet.options.index > options.index && sheet.options.insertionPoint === options.insertionPoint) {
                        return sheet;
                    }
                }

                return null;
            }
            /**
             * Find attached sheet with the highest index.
             */


            function findHighestSheet(registry, options) {
                for (var i = registry.length - 1; i >= 0; i--) {
                    var sheet = registry[i];

                    if (sheet.attached && sheet.options.insertionPoint === options.insertionPoint) {
                        return sheet;
                    }
                }

                return null;
            }
            /**
             * Find a comment with "jss" inside.
             */


            function findCommentNode(text) {
                var head = getHead();

                for (var i = 0; i < head.childNodes.length; i++) {
                    var node = head.childNodes[i];

                    if (node.nodeType === 8 && node.nodeValue.trim() === text) {
                        return node;
                    }
                }

                return null;
            }

            /**
             * Find a node before which we can insert the sheet.
             */
            function findPrevNode(options) {
                var registry = sheets.registry;

                if (registry.length > 0) {
                    // Try to insert before the next higher sheet.
                    var sheet = findHigherSheet(registry, options);

                    if (sheet && sheet.renderer) {
                        return {
                            parent: sheet.renderer.element.parentNode,
                            node: sheet.renderer.element
                        };
                    } // Otherwise insert after the last attached.


                    sheet = findHighestSheet(registry, options);

                    if (sheet && sheet.renderer) {
                        return {
                            parent: sheet.renderer.element.parentNode,
                            node: sheet.renderer.element.nextSibling
                        };
                    }
                } // Try to find a comment placeholder if registry is empty.


                var insertionPoint = options.insertionPoint;

                if (insertionPoint && typeof insertionPoint === 'string') {
                    var comment = findCommentNode(insertionPoint);

                    if (comment) {
                        return {
                            parent: comment.parentNode,
                            node: comment.nextSibling
                        };
                    } // If user specifies an insertion point and it can't be found in the document -
                    // bad specificity issues may appear.


                    true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] Insertion point \"" + insertionPoint + "\" not found.") : undefined;
                }

                return false;
            }
            /**
             * Insert style element into the DOM.
             */


            function insertStyle(style, options) {
                var insertionPoint = options.insertionPoint;
                var nextNode = findPrevNode(options);

                if (nextNode !== false && nextNode.parent) {
                    nextNode.parent.insertBefore(style, nextNode.node);
                    return;
                } // Works with iframes and any node types.


                if (insertionPoint && typeof insertionPoint.nodeType === 'number') {
                    // https://stackoverflow.com/questions/41328728/force-casting-in-flow
                    var insertionPointElement = insertionPoint;
                    var parentNode = insertionPointElement.parentNode;
                    if (parentNode) parentNode.insertBefore(style, insertionPointElement.nextSibling); else true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, '[JSS] Insertion point is not in the DOM.') : undefined;
                    return;
                }

                getHead().appendChild(style);
            }
            /**
             * Read jss nonce setting from the page if the user has set it.
             */


            var getNonce = memoize(function () {
                var node = document.querySelector('meta[property="csp-nonce"]');
                return node ? node.getAttribute('content') : null;
            });

            var _insertRule = function insertRule(container, rule, index) {
                var maxIndex = container.cssRules.length; // In case previous insertion fails, passed index might be wrong

                if (index === undefined || index > maxIndex) {
                    // eslint-disable-next-line no-param-reassign
                    index = maxIndex;
                }

                try {
                    if ('insertRule' in container) {
                        var c = container;
                        c.insertRule(rule, index);
                    } // Keyframes rule.
                    else if ('appendRule' in container) {
                        var _c = container;

                        _c.appendRule(rule);
                    }
                } catch (err) {
                    true ? Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] " + err.message) : undefined;
                    return false;
                }

                return container.cssRules[index];
            };

            var createStyle = function createStyle() {
                var el = document.createElement('style'); // Without it, IE will have a broken source order specificity if we
                // insert rules after we insert the style tag.
                // It seems to kick-off the source order specificity algorithm.

                el.textContent = '\n';
                return el;
            };

            var DomRenderer =
                /*#__PURE__*/
                function () {
                    // HTMLStyleElement needs fixing https://github.com/facebook/flow/issues/2696
                    function DomRenderer(sheet) {
                        this.getPropertyValue = getPropertyValue;
                        this.setProperty = setProperty;
                        this.removeProperty = removeProperty;
                        this.setSelector = setSelector;
                        this.element = void 0;
                        this.sheet = void 0;
                        this.hasInsertedRules = false;
                        // There is no sheet when the renderer is used from a standalone StyleRule.
                        if (sheet) sheets.add(sheet);
                        this.sheet = sheet;

                        var _ref = this.sheet ? this.sheet.options : {},
                            media = _ref.media,
                            meta = _ref.meta,
                            element = _ref.element;

                        this.element = element || createStyle();
                        this.element.setAttribute('data-jss', '');
                        if (media) this.element.setAttribute('media', media);
                        if (meta) this.element.setAttribute('data-meta', meta);
                        var nonce = getNonce();
                        if (nonce) this.element.setAttribute('nonce', nonce);
                    }
                    /**
                     * Insert style element into render tree.
                     */


                    var _proto = DomRenderer.prototype;

                    _proto.attach = function attach() {
                        // In the case the element node is external and it is already in the DOM.
                        if (this.element.parentNode || !this.sheet) return;
                        insertStyle(this.element, this.sheet.options); // When rules are inserted using `insertRule` API, after `sheet.detach().attach()`
                        // most browsers create a new CSSStyleSheet, except of all IEs.

                        var deployed = Boolean(this.sheet && this.sheet.deployed);

                        if (this.hasInsertedRules && deployed) {
                            this.hasInsertedRules = false;
                            this.deploy();
                        }
                    }
                        /**
                         * Remove style element from render tree.
                         */
                        ;

                    _proto.detach = function detach() {
                        var parentNode = this.element.parentNode;
                        if (parentNode) parentNode.removeChild(this.element);
                    }
                        /**
                         * Inject CSS string into element.
                         */
                        ;

                    _proto.deploy = function deploy() {
                        var sheet = this.sheet;
                        if (!sheet) return;

                        if (sheet.options.link) {
                            this.insertRules(sheet.rules);
                            return;
                        }

                        this.element.textContent = "\n" + sheet.toString() + "\n";
                    }
                        /**
                         * Insert RuleList into an element.
                         */
                        ;

                    _proto.insertRules = function insertRules(rules, nativeParent) {
                        for (var i = 0; i < rules.index.length; i++) {
                            this.insertRule(rules.index[i], i, nativeParent);
                        }
                    }
                        /**
                         * Insert a rule into element.
                         */
                        ;

                    _proto.insertRule = function insertRule(rule, index, nativeParent) {
                        if (nativeParent === void 0) {
                            nativeParent = this.element.sheet;
                        }

                        if (rule.rules) {
                            var parent = rule;
                            var latestNativeParent = nativeParent;

                            if (rule.type === 'conditional' || rule.type === 'keyframes') {
                                // We need to render the container without children first.
                                latestNativeParent = _insertRule(nativeParent, parent.toString({
                                    children: false
                                }), index);

                                if (latestNativeParent === false) {
                                    return false;
                                }
                            }

                            this.insertRules(parent.rules, latestNativeParent);
                            return latestNativeParent;
                        } // IE keeps the CSSStyleSheet after style node has been reattached,
                        // so we need to check if the `renderable` reference the right style sheet and not
                        // rerender those rules.


                        if (rule.renderable && rule.renderable.parentStyleSheet === this.element.sheet) {
                            return rule.renderable;
                        }

                        var ruleStr = rule.toString();
                        if (!ruleStr) return false;

                        var nativeRule = _insertRule(nativeParent, ruleStr, index);

                        if (nativeRule === false) {
                            return false;
                        }

                        this.hasInsertedRules = true;
                        rule.renderable = nativeRule;
                        return nativeRule;
                    }
                        /**
                         * Delete a rule.
                         */
                        ;

                    _proto.deleteRule = function deleteRule(cssRule) {
                        var sheet = this.element.sheet;
                        var index = this.indexOf(cssRule);
                        if (index === -1) return false;
                        sheet.deleteRule(index);
                        return true;
                    }
                        /**
                         * Get index of a CSS Rule.
                         */
                        ;

                    _proto.indexOf = function indexOf(cssRule) {
                        var cssRules = this.element.sheet.cssRules;

                        for (var index = 0; index < cssRules.length; index++) {
                            if (cssRule === cssRules[index]) return index;
                        }

                        return -1;
                    }
                        /**
                         * Generate a new CSS rule and replace the existing one.
                         *
                         * Only used for some old browsers because they can't set a selector.
                         */
                        ;

                    _proto.replaceRule = function replaceRule(cssRule, rule) {
                        var index = this.indexOf(cssRule);
                        if (index === -1) return false;
                        this.element.sheet.deleteRule(index);
                        return this.insertRule(rule, index);
                    }
                        /**
                         * Get all rules elements.
                         */
                        ;

                    _proto.getRules = function getRules() {
                        return this.element.sheet.cssRules;
                    };

                    return DomRenderer;
                }();

            var instanceCounter = 0;

            var Jss =
                /*#__PURE__*/
                function () {
                    function Jss(options) {
                        this.id = instanceCounter++;
                        this.version = "10.0.0";
                        this.plugins = new PluginsRegistry();
                        this.options = {
                            id: {
                                minify: false
                            },
                            createGenerateId: createGenerateId,
                            Renderer: is_in_browser__WEBPACK_IMPORTED_MODULE_1__["default"] ? DomRenderer : null,
                            plugins: []
                        };
                        this.generateId = createGenerateId({
                            minify: false
                        });

                        for (var i = 0; i < plugins.length; i++) {
                            this.plugins.use(plugins[i], {
                                queue: 'internal'
                            });
                        }

                        this.setup(options);
                    }
                    /**
                     * Prepares various options, applies plugins.
                     * Should not be used twice on the same instance, because there is no plugins
                     * deduplication logic.
                     */


                    var _proto = Jss.prototype;

                    _proto.setup = function setup(options) {
                        if (options === void 0) {
                            options = {};
                        }

                        if (options.createGenerateId) {
                            this.options.createGenerateId = options.createGenerateId;
                        }

                        if (options.id) {
                            this.options.id = Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, this.options.id, options.id);
                        }

                        if (options.createGenerateId || options.id) {
                            this.generateId = this.options.createGenerateId(this.options.id);
                        }

                        if (options.insertionPoint != null) this.options.insertionPoint = options.insertionPoint;

                        if ('Renderer' in options) {
                            this.options.Renderer = options.Renderer;
                        } // eslint-disable-next-line prefer-spread


                        if (options.plugins) this.use.apply(this, options.plugins);
                        return this;
                    }
                        /**
                         * Create a Style Sheet.
                         */
                        ;

                    _proto.createStyleSheet = function createStyleSheet(styles, options) {
                        if (options === void 0) {
                            options = {};
                        }

                        var _options = options,
                            index = _options.index;

                        if (typeof index !== 'number') {
                            index = sheets.index === 0 ? 0 : sheets.index + 1;
                        }

                        var sheet = new StyleSheet(styles, Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            jss: this,
                            generateId: options.generateId || this.generateId,
                            insertionPoint: this.options.insertionPoint,
                            Renderer: this.options.Renderer,
                            index: index
                        }));
                        this.plugins.onProcessSheet(sheet);
                        return sheet;
                    }
                        /**
                         * Detach the Style Sheet and remove it from the registry.
                         */
                        ;

                    _proto.removeStyleSheet = function removeStyleSheet(sheet) {
                        sheet.detach();
                        sheets.remove(sheet);
                        return this;
                    }
                        /**
                         * Create a rule without a Style Sheet.
                         */
                        ;

                    _proto.createRule = function createRule$$1(name, style, options) {
                        if (style === void 0) {
                            style = {};
                        }

                        if (options === void 0) {
                            options = {};
                        }

                        // Enable rule without name for inline styles.
                        if (typeof name === 'object') {
                            return this.createRule(undefined, name, style);
                        }

                        var ruleOptions = Object(_babel_runtime_helpers_esm_extends__WEBPACK_IMPORTED_MODULE_0__["default"])({}, options, {
                            jss: this,
                            Renderer: this.options.Renderer
                        });

                        if (!ruleOptions.generateId) ruleOptions.generateId = this.generateId;
                        if (!ruleOptions.classes) ruleOptions.classes = {};
                        if (!ruleOptions.keyframes) ruleOptions.keyframes = {};

                        var rule = createRule(name, style, ruleOptions);

                        if (rule) this.plugins.onProcessRule(rule);
                        return rule;
                    }
                        /**
                         * Register plugin. Passed function will be invoked with a rule instance.
                         */
                        ;

                    _proto.use = function use() {
                        var _this = this;

                        for (var _len = arguments.length, plugins$$1 = new Array(_len), _key = 0; _key < _len; _key++) {
                            plugins$$1[_key] = arguments[_key];
                        }

                        plugins$$1.forEach(function (plugin) {
                            _this.plugins.use(plugin);
                        });
                        return this;
                    };

                    return Jss;
                }();

            /**
             * Extracts a styles object with only props that contain function values.
             */
            function getDynamicStyles(styles) {
                var to = null;

                for (var key in styles) {
                    var value = styles[key];
                    var type = typeof value;

                    if (type === 'function') {
                        if (!to) to = {};
                        to[key] = value;
                    } else if (type === 'object' && value !== null && !Array.isArray(value)) {
                        var extracted = getDynamicStyles(value);

                        if (extracted) {
                            if (!to) to = {};
                            to[key] = extracted;
                        }
                    }
                }

                return to;
            }

            /**
             * SheetsManager is like a WeakMap which is designed to count StyleSheet
             * instances and attach/detach automatically.
             */
            var SheetsManager =
                /*#__PURE__*/
                function () {
                    function SheetsManager() {
                        this.length = 0;
                        this.sheets = new WeakMap();
                    }

                    var _proto = SheetsManager.prototype;

                    _proto.get = function get(key) {
                        var entry = this.sheets.get(key);
                        return entry && entry.sheet;
                    };

                    _proto.add = function add(key, sheet) {
                        if (this.sheets.has(key)) return;
                        this.length++;
                        this.sheets.set(key, {
                            sheet: sheet,
                            refs: 0
                        });
                    };

                    _proto.manage = function manage(key) {
                        var entry = this.sheets.get(key);

                        if (entry) {
                            if (entry.refs === 0) {
                                entry.sheet.attach();
                            }

                            entry.refs++;
                            return entry.sheet;
                        }

                        Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "[JSS] SheetsManager: can't find sheet to manage");
                        return undefined;
                    };

                    _proto.unmanage = function unmanage(key) {
                        var entry = this.sheets.get(key);

                        if (entry) {
                            if (entry.refs > 0) {
                                entry.refs--;
                                if (entry.refs === 0) entry.sheet.detach();
                            }
                        } else {
                            Object(tiny_warning__WEBPACK_IMPORTED_MODULE_2__["default"])(false, "SheetsManager: can't find sheet to unmanage");
                        }
                    };

                    Object(_babel_runtime_helpers_esm_createClass__WEBPACK_IMPORTED_MODULE_3__["default"])(SheetsManager, [{
                        key: "size",
                        get: function get() {
                            return this.length;
                        }
                    }]);

                    return SheetsManager;
                }();

            /**
             * A better abstraction over CSS.
             *
             * @copyright Oleg Isonen (Slobodskoi) / Isonen 2014-present
             * @website https://github.com/cssinjs/jss
             * @license MIT
             */

            /**
             * Export a constant indicating if this browser has CSSTOM support.
             * https://developers.google.com/web/updates/2018/03/cssom
             */
            var hasCSSTOMSupport = typeof CSS !== 'undefined' && CSS && 'number' in CSS;
            /**
             * Creates a new instance of Jss.
             */

            var create = function create(options) {
                return new Jss(options);
            };
            /**
             * A global Jss instance.
             */

            var index = create();

/* harmony default export */ __webpack_exports__["default"] = (index);



            /***/
        }),

/***/ "./node_modules/process/browser.js":
/*!*****************************************!*\
  !*** ./node_modules/process/browser.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function (module, exports) {

            // shim for using process in browser
            var process = module.exports = {};

            // cached from whatever global is present so that test runners that stub it
            // don't break things.  But we need to wrap it in a try catch in case it is
            // wrapped in strict mode code which doesn't define any globals.  It's inside a
            // function because try/catches deoptimize in certain engines.

            var cachedSetTimeout;
            var cachedClearTimeout;

            function defaultSetTimout() {
                throw new Error('setTimeout has not been defined');
            }
            function defaultClearTimeout() {
                throw new Error('clearTimeout has not been defined');
            }
            (function () {
                try {
                    if (typeof setTimeout === 'function') {
                        cachedSetTimeout = setTimeout;
                    } else {
                        cachedSetTimeout = defaultSetTimout;
                    }
                } catch (e) {
                    cachedSetTimeout = defaultSetTimout;
                }
                try {
                    if (typeof clearTimeout === 'function') {
                        cachedClearTimeout = clearTimeout;
                    } else {
                        cachedClearTimeout = defaultClearTimeout;
                    }
                } catch (e) {
                    cachedClearTimeout = defaultClearTimeout;
                }
            }())
            function runTimeout(fun) {
                if (cachedSetTimeout === setTimeout) {
                    //normal enviroments in sane situations
                    return setTimeout(fun, 0);
                }
                // if setTimeout wasn't available but was latter defined
                if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
                    cachedSetTimeout = setTimeout;
                    return setTimeout(fun, 0);
                }
                try {
                    // when when somebody has screwed with setTimeout but no I.E. maddness
                    return cachedSetTimeout(fun, 0);
                } catch (e) {
                    try {
                        // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
                        return cachedSetTimeout.call(null, fun, 0);
                    } catch (e) {
                        // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
                        return cachedSetTimeout.call(this, fun, 0);
                    }
                }


            }
            function runClearTimeout(marker) {
                if (cachedClearTimeout === clearTimeout) {
                    //normal enviroments in sane situations
                    return clearTimeout(marker);
                }
                // if clearTimeout wasn't available but was latter defined
                if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
                    cachedClearTimeout = clearTimeout;
                    return clearTimeout(marker);
                }
                try {
                    // when when somebody has screwed with setTimeout but no I.E. maddness
                    return cachedClearTimeout(marker);
                } catch (e) {
                    try {
                        // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
                        return cachedClearTimeout.call(null, marker);
                    } catch (e) {
                        // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
                        // Some versions of I.E. have different rules for clearTimeout vs setTimeout
                        return cachedClearTimeout.call(this, marker);
                    }
                }



            }
            var queue = [];
            var draining = false;
            var currentQueue;
            var queueIndex = -1;

            function cleanUpNextTick() {
                if (!draining || !currentQueue) {
                    return;
                }
                draining = false;
                if (currentQueue.length) {
                    queue = currentQueue.concat(queue);
                } else {
                    queueIndex = -1;
                }
                if (queue.length) {
                    drainQueue();
                }
            }

            function drainQueue() {
                if (draining) {
                    return;
                }
                var timeout = runTimeout(cleanUpNextTick);
                draining = true;

                var len = queue.length;
                while (len) {
                    currentQueue = queue;
                    queue = [];
                    while (++queueIndex < len) {
                        if (currentQueue) {
                            currentQueue[queueIndex].run();
                        }
                    }
                    queueIndex = -1;
                    len = queue.length;
                }
                currentQueue = null;
                draining = false;
                runClearTimeout(timeout);
            }

            process.nextTick = function (fun) {
                var args = new Array(arguments.length - 1);
                if (arguments.length > 1) {
                    for (var i = 1; i < arguments.length; i++) {
                        args[i - 1] = arguments[i];
                    }
                }
                queue.push(new Item(fun, args));
                if (queue.length === 1 && !draining) {
                    runTimeout(drainQueue);
                }
            };

            // v8 likes predictible objects
            function Item(fun, array) {
                this.fun = fun;
                this.array = array;
            }
            Item.prototype.run = function () {
                this.fun.apply(null, this.array);
            };
            process.title = 'browser';
            process.browser = true;
            process.env = {};
            process.argv = [];
            process.version = ''; // empty string to avoid regexp issues
            process.versions = {};

            function noop() { }

            process.on = noop;
            process.addListener = noop;
            process.once = noop;
            process.off = noop;
            process.removeListener = noop;
            process.removeAllListeners = noop;
            process.emit = noop;
            process.prependListener = noop;
            process.prependOnceListener = noop;

            process.listeners = function (name) { return [] }

            process.binding = function (name) {
                throw new Error('process.binding is not supported');
            };

            process.cwd = function () { return '/' };
            process.chdir = function (dir) {
                throw new Error('process.chdir is not supported');
            };
            process.umask = function () { return 0; };


            /***/
        }),

/***/ "./node_modules/setimmediate/setImmediate.js":
/*!***************************************************!*\
  !*** ./node_modules/setimmediate/setImmediate.js ***!
  \***************************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function (global, process) {
                (function (global, undefined) {
                    "use strict";

                    if (global.setImmediate) {
                        return;
                    }

                    var nextHandle = 1; // Spec says greater than zero
                    var tasksByHandle = {};
                    var currentlyRunningATask = false;
                    var doc = global.document;
                    var registerImmediate;

                    function setImmediate(callback) {
                        // Callback can either be a function or a string
                        if (typeof callback !== "function") {
                            callback = new Function("" + callback);
                        }
                        // Copy function arguments
                        var args = new Array(arguments.length - 1);
                        for (var i = 0; i < args.length; i++) {
                            args[i] = arguments[i + 1];
                        }
                        // Store and register the task
                        var task = { callback: callback, args: args };
                        tasksByHandle[nextHandle] = task;
                        registerImmediate(nextHandle);
                        return nextHandle++;
                    }

                    function clearImmediate(handle) {
                        delete tasksByHandle[handle];
                    }

                    function run(task) {
                        var callback = task.callback;
                        var args = task.args;
                        switch (args.length) {
                            case 0:
                                callback();
                                break;
                            case 1:
                                callback(args[0]);
                                break;
                            case 2:
                                callback(args[0], args[1]);
                                break;
                            case 3:
                                callback(args[0], args[1], args[2]);
                                break;
                            default:
                                callback.apply(undefined, args);
                                break;
                        }
                    }

                    function runIfPresent(handle) {
                        // From the spec: "Wait until any invocations of this algorithm started before this one have completed."
                        // So if we're currently running a task, we'll need to delay this invocation.
                        if (currentlyRunningATask) {
                            // Delay by doing a setTimeout. setImmediate was tried instead, but in Firefox 7 it generated a
                            // "too much recursion" error.
                            setTimeout(runIfPresent, 0, handle);
                        } else {
                            var task = tasksByHandle[handle];
                            if (task) {
                                currentlyRunningATask = true;
                                try {
                                    run(task);
                                } finally {
                                    clearImmediate(handle);
                                    currentlyRunningATask = false;
                                }
                            }
                        }
                    }

                    function installNextTickImplementation() {
                        registerImmediate = function (handle) {
                            process.nextTick(function () { runIfPresent(handle); });
                        };
                    }

                    function canUsePostMessage() {
                        // The test against `importScripts` prevents this implementation from being installed inside a web worker,
                        // where `global.postMessage` means something completely different and can't be used for this purpose.
                        if (global.postMessage && !global.importScripts) {
                            var postMessageIsAsynchronous = true;
                            var oldOnMessage = global.onmessage;
                            global.onmessage = function () {
                                postMessageIsAsynchronous = false;
                            };
                            global.postMessage("", "*");
                            global.onmessage = oldOnMessage;
                            return postMessageIsAsynchronous;
                        }
                    }

                    function installPostMessageImplementation() {
                        // Installs an event handler on `global` for the `message` event: see
                        // * https://developer.mozilla.org/en/DOM/window.postMessage
                        // * http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html#crossDocumentMessages

                        var messagePrefix = "setImmediate$" + Math.random() + "$";
                        var onGlobalMessage = function (event) {
                            if (event.source === global &&
                                typeof event.data === "string" &&
                                event.data.indexOf(messagePrefix) === 0) {
                                runIfPresent(+event.data.slice(messagePrefix.length));
                            }
                        };

                        if (global.addEventListener) {
                            global.addEventListener("message", onGlobalMessage, false);
                        } else {
                            global.attachEvent("onmessage", onGlobalMessage);
                        }

                        registerImmediate = function (handle) {
                            global.postMessage(messagePrefix + handle, "*");
                        };
                    }

                    function installMessageChannelImplementation() {
                        var channel = new MessageChannel();
                        channel.port1.onmessage = function (event) {
                            var handle = event.data;
                            runIfPresent(handle);
                        };

                        registerImmediate = function (handle) {
                            channel.port2.postMessage(handle);
                        };
                    }

                    function installReadyStateChangeImplementation() {
                        var html = doc.documentElement;
                        registerImmediate = function (handle) {
                            // Create a <script> element; its readystatechange event will be fired asynchronously once it is inserted
                            // into the document. Do so, thus queuing up the task. Remember to clean up once it's been called.
                            var script = doc.createElement("script");
                            script.onreadystatechange = function () {
                                runIfPresent(handle);
                                script.onreadystatechange = null;
                                html.removeChild(script);
                                script = null;
                            };
                            html.appendChild(script);
                        };
                    }

                    function installSetTimeoutImplementation() {
                        registerImmediate = function (handle) {
                            setTimeout(runIfPresent, 0, handle);
                        };
                    }

                    // If supported, we should attach to the prototype of global, since that is where setTimeout et al. live.
                    var attachTo = Object.getPrototypeOf && Object.getPrototypeOf(global);
                    attachTo = attachTo && attachTo.setTimeout ? attachTo : global;

                    // Don't get fooled by e.g. browserify environments.
                    if ({}.toString.call(global.process) === "[object process]") {
                        // For Node.js before 0.9
                        installNextTickImplementation();

                    } else if (canUsePostMessage()) {
                        // For non-IE10 modern browsers
                        installPostMessageImplementation();

                    } else if (global.MessageChannel) {
                        // For web workers, where supported
                        installMessageChannelImplementation();

                    } else if (doc && "onreadystatechange" in doc.createElement("script")) {
                        // For IE 6–8
                        installReadyStateChangeImplementation();

                    } else {
                        // For older browsers
                        installSetTimeoutImplementation();
                    }

                    attachTo.setImmediate = setImmediate;
                    attachTo.clearImmediate = clearImmediate;
                }(typeof self === "undefined" ? typeof global === "undefined" ? this : global : self));

                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js"), __webpack_require__(/*! ./../process/browser.js */ "./node_modules/process/browser.js")))

            /***/
        }),

/***/ "./node_modules/symbol-observable/es/index.js":
/*!****************************************************!*\
  !*** ./node_modules/symbol-observable/es/index.js ***!
  \****************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* WEBPACK VAR INJECTION */(function (global, module) {/* harmony import */ var _ponyfill_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ponyfill.js */ "./node_modules/symbol-observable/es/ponyfill.js");
                /* global window */


                var root;

                if (typeof self !== 'undefined') {
                    root = self;
                } else if (typeof window !== 'undefined') {
                    root = window;
                } else if (typeof global !== 'undefined') {
                    root = global;
                } else if (true) {
                    root = module;
                } else { }

                var result = Object(_ponyfill_js__WEBPACK_IMPORTED_MODULE_0__["default"])(root);
/* harmony default export */ __webpack_exports__["default"] = (result);

                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js"), __webpack_require__(/*! ./../../webpack/buildin/harmony-module.js */ "./node_modules/webpack/buildin/harmony-module.js")(module)))

            /***/
        }),

/***/ "./node_modules/symbol-observable/es/ponyfill.js":
/*!*******************************************************!*\
  !*** ./node_modules/symbol-observable/es/ponyfill.js ***!
  \*******************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function () { return symbolObservablePonyfill; });
            function symbolObservablePonyfill(root) {
                var result;
                var Symbol = root.Symbol;

                if (typeof Symbol === 'function') {
                    if (Symbol.observable) {
                        result = Symbol.observable;
                    } else {
                        result = Symbol('observable');
                        Symbol.observable = result;
                    }
                } else {
                    result = '@@observable';
                }

                return result;
            };


            /***/
        }),

/***/ "./node_modules/timers-browserify/main.js":
/*!************************************************!*\
  !*** ./node_modules/timers-browserify/main.js ***!
  \************************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function (global) {
                var scope = (typeof global !== "undefined" && global) ||
                    (typeof self !== "undefined" && self) ||
                    window;
                var apply = Function.prototype.apply;

                // DOM APIs, for completeness

                exports.setTimeout = function () {
                    return new Timeout(apply.call(setTimeout, scope, arguments), clearTimeout);
                };
                exports.setInterval = function () {
                    return new Timeout(apply.call(setInterval, scope, arguments), clearInterval);
                };
                exports.clearTimeout =
                    exports.clearInterval = function (timeout) {
                        if (timeout) {
                            timeout.close();
                        }
                    };

                function Timeout(id, clearFn) {
                    this._id = id;
                    this._clearFn = clearFn;
                }
                Timeout.prototype.unref = Timeout.prototype.ref = function () { };
                Timeout.prototype.close = function () {
                    this._clearFn.call(scope, this._id);
                };

                // Does not start the time, just sets up the members needed.
                exports.enroll = function (item, msecs) {
                    clearTimeout(item._idleTimeoutId);
                    item._idleTimeout = msecs;
                };

                exports.unenroll = function (item) {
                    clearTimeout(item._idleTimeoutId);
                    item._idleTimeout = -1;
                };

                exports._unrefActive = exports.active = function (item) {
                    clearTimeout(item._idleTimeoutId);

                    var msecs = item._idleTimeout;
                    if (msecs >= 0) {
                        item._idleTimeoutId = setTimeout(function onTimeout() {
                            if (item._onTimeout)
                                item._onTimeout();
                        }, msecs);
                    }
                };

                // setimmediate attaches itself to the global object
                __webpack_require__(/*! setimmediate */ "./node_modules/setimmediate/setImmediate.js");
                // On some exotic environments, it's not clear which object `setimmediate` was
                // able to install onto.  Search each possibility in the same order as the
                // `setimmediate` library.
                exports.setImmediate = (typeof self !== "undefined" && self.setImmediate) ||
                    (typeof global !== "undefined" && global.setImmediate) ||
                    (this && this.setImmediate);
                exports.clearImmediate = (typeof self !== "undefined" && self.clearImmediate) ||
                    (typeof global !== "undefined" && global.clearImmediate) ||
                    (this && this.clearImmediate);

                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js")))

            /***/
        }),

/***/ "./node_modules/tiny-warning/dist/tiny-warning.esm.js":
/*!************************************************************!*\
  !*** ./node_modules/tiny-warning/dist/tiny-warning.esm.js ***!
  \************************************************************/
/*! exports provided: default */
/***/ (function (module, __webpack_exports__, __webpack_require__) {

            "use strict";
            __webpack_require__.r(__webpack_exports__);
            var isProduction = "development" === 'production';
            function warning(condition, message) {
                if (!isProduction) {
                    if (condition) {
                        return;
                    }

                    var text = "Warning: " + message;

                    if (typeof console !== 'undefined') {
                        console.warn(text);
                    }

                    try {
                        throw Error(text);
                    } catch (x) { }
                }
            }

/* harmony default export */ __webpack_exports__["default"] = (warning);


            /***/
        }),

/***/ "./node_modules/vue/dist/vue.min.js":
/*!******************************************!*\
  !*** ./node_modules/vue/dist/vue.min.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function (module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function (global, setImmediate) {/*!
 * Vue.js v2.6.10
 * (c) 2014-2019 Evan You
 * Released under the MIT License.
 */
                !function (e, t) { true ? module.exports = t() : undefined }(this, function () { "use strict"; var e = Object.freeze({}); function t(e) { return null == e } function n(e) { return null != e } function r(e) { return !0 === e } function i(e) { return "string" == typeof e || "number" == typeof e || "symbol" == typeof e || "boolean" == typeof e } function o(e) { return null !== e && "object" == typeof e } var a = Object.prototype.toString; function s(e) { return "[object Object]" === a.call(e) } function c(e) { var t = parseFloat(String(e)); return t >= 0 && Math.floor(t) === t && isFinite(e) } function u(e) { return n(e) && "function" == typeof e.then && "function" == typeof e.catch } function l(e) { return null == e ? "" : Array.isArray(e) || s(e) && e.toString === a ? JSON.stringify(e, null, 2) : String(e) } function f(e) { var t = parseFloat(e); return isNaN(t) ? e : t } function p(e, t) { for (var n = Object.create(null), r = e.split(","), i = 0; i < r.length; i++)n[r[i]] = !0; return t ? function (e) { return n[e.toLowerCase()] } : function (e) { return n[e] } } var d = p("slot,component", !0), v = p("key,ref,slot,slot-scope,is"); function h(e, t) { if (e.length) { var n = e.indexOf(t); if (n > -1) return e.splice(n, 1) } } var m = Object.prototype.hasOwnProperty; function y(e, t) { return m.call(e, t) } function g(e) { var t = Object.create(null); return function (n) { return t[n] || (t[n] = e(n)) } } var _ = /-(\w)/g, b = g(function (e) { return e.replace(_, function (e, t) { return t ? t.toUpperCase() : "" }) }), $ = g(function (e) { return e.charAt(0).toUpperCase() + e.slice(1) }), w = /\B([A-Z])/g, C = g(function (e) { return e.replace(w, "-$1").toLowerCase() }); var x = Function.prototype.bind ? function (e, t) { return e.bind(t) } : function (e, t) { function n(n) { var r = arguments.length; return r ? r > 1 ? e.apply(t, arguments) : e.call(t, n) : e.call(t) } return n._length = e.length, n }; function k(e, t) { t = t || 0; for (var n = e.length - t, r = new Array(n); n--;)r[n] = e[n + t]; return r } function A(e, t) { for (var n in t) e[n] = t[n]; return e } function O(e) { for (var t = {}, n = 0; n < e.length; n++)e[n] && A(t, e[n]); return t } function S(e, t, n) { } var T = function (e, t, n) { return !1 }, E = function (e) { return e }; function N(e, t) { if (e === t) return !0; var n = o(e), r = o(t); if (!n || !r) return !n && !r && String(e) === String(t); try { var i = Array.isArray(e), a = Array.isArray(t); if (i && a) return e.length === t.length && e.every(function (e, n) { return N(e, t[n]) }); if (e instanceof Date && t instanceof Date) return e.getTime() === t.getTime(); if (i || a) return !1; var s = Object.keys(e), c = Object.keys(t); return s.length === c.length && s.every(function (n) { return N(e[n], t[n]) }) } catch (e) { return !1 } } function j(e, t) { for (var n = 0; n < e.length; n++)if (N(e[n], t)) return n; return -1 } function D(e) { var t = !1; return function () { t || (t = !0, e.apply(this, arguments)) } } var L = "data-server-rendered", M = ["component", "directive", "filter"], I = ["beforeCreate", "created", "beforeMount", "mounted", "beforeUpdate", "updated", "beforeDestroy", "destroyed", "activated", "deactivated", "errorCaptured", "serverPrefetch"], F = { optionMergeStrategies: Object.create(null), silent: !1, productionTip: !1, devtools: !1, performance: !1, errorHandler: null, warnHandler: null, ignoredElements: [], keyCodes: Object.create(null), isReservedTag: T, isReservedAttr: T, isUnknownElement: T, getTagNamespace: S, parsePlatformTagName: E, mustUseProp: T, async: !0, _lifecycleHooks: I }, P = /a-zA-Z\u00B7\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u037D\u037F-\u1FFF\u200C-\u200D\u203F-\u2040\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD/; function R(e, t, n, r) { Object.defineProperty(e, t, { value: n, enumerable: !!r, writable: !0, configurable: !0 }) } var H = new RegExp("[^" + P.source + ".$_\\d]"); var B, U = "__proto__" in {}, z = "undefined" != typeof window, V = "undefined" != typeof WXEnvironment && !!WXEnvironment.platform, K = V && WXEnvironment.platform.toLowerCase(), J = z && window.navigator.userAgent.toLowerCase(), q = J && /msie|trident/.test(J), W = J && J.indexOf("msie 9.0") > 0, Z = J && J.indexOf("edge/") > 0, G = (J && J.indexOf("android"), J && /iphone|ipad|ipod|ios/.test(J) || "ios" === K), X = (J && /chrome\/\d+/.test(J), J && /phantomjs/.test(J), J && J.match(/firefox\/(\d+)/)), Y = {}.watch, Q = !1; if (z) try { var ee = {}; Object.defineProperty(ee, "passive", { get: function () { Q = !0 } }), window.addEventListener("test-passive", null, ee) } catch (e) { } var te = function () { return void 0 === B && (B = !z && !V && "undefined" != typeof global && (global.process && "server" === global.process.env.VUE_ENV)), B }, ne = z && window.__VUE_DEVTOOLS_GLOBAL_HOOK__; function re(e) { return "function" == typeof e && /native code/.test(e.toString()) } var ie, oe = "undefined" != typeof Symbol && re(Symbol) && "undefined" != typeof Reflect && re(Reflect.ownKeys); ie = "undefined" != typeof Set && re(Set) ? Set : function () { function e() { this.set = Object.create(null) } return e.prototype.has = function (e) { return !0 === this.set[e] }, e.prototype.add = function (e) { this.set[e] = !0 }, e.prototype.clear = function () { this.set = Object.create(null) }, e }(); var ae = S, se = 0, ce = function () { this.id = se++ , this.subs = [] }; ce.prototype.addSub = function (e) { this.subs.push(e) }, ce.prototype.removeSub = function (e) { h(this.subs, e) }, ce.prototype.depend = function () { ce.target && ce.target.addDep(this) }, ce.prototype.notify = function () { for (var e = this.subs.slice(), t = 0, n = e.length; t < n; t++)e[t].update() }, ce.target = null; var ue = []; function le(e) { ue.push(e), ce.target = e } function fe() { ue.pop(), ce.target = ue[ue.length - 1] } var pe = function (e, t, n, r, i, o, a, s) { this.tag = e, this.data = t, this.children = n, this.text = r, this.elm = i, this.ns = void 0, this.context = o, this.fnContext = void 0, this.fnOptions = void 0, this.fnScopeId = void 0, this.key = t && t.key, this.componentOptions = a, this.componentInstance = void 0, this.parent = void 0, this.raw = !1, this.isStatic = !1, this.isRootInsert = !0, this.isComment = !1, this.isCloned = !1, this.isOnce = !1, this.asyncFactory = s, this.asyncMeta = void 0, this.isAsyncPlaceholder = !1 }, de = { child: { configurable: !0 } }; de.child.get = function () { return this.componentInstance }, Object.defineProperties(pe.prototype, de); var ve = function (e) { void 0 === e && (e = ""); var t = new pe; return t.text = e, t.isComment = !0, t }; function he(e) { return new pe(void 0, void 0, void 0, String(e)) } function me(e) { var t = new pe(e.tag, e.data, e.children && e.children.slice(), e.text, e.elm, e.context, e.componentOptions, e.asyncFactory); return t.ns = e.ns, t.isStatic = e.isStatic, t.key = e.key, t.isComment = e.isComment, t.fnContext = e.fnContext, t.fnOptions = e.fnOptions, t.fnScopeId = e.fnScopeId, t.asyncMeta = e.asyncMeta, t.isCloned = !0, t } var ye = Array.prototype, ge = Object.create(ye);["push", "pop", "shift", "unshift", "splice", "sort", "reverse"].forEach(function (e) { var t = ye[e]; R(ge, e, function () { for (var n = [], r = arguments.length; r--;)n[r] = arguments[r]; var i, o = t.apply(this, n), a = this.__ob__; switch (e) { case "push": case "unshift": i = n; break; case "splice": i = n.slice(2) }return i && a.observeArray(i), a.dep.notify(), o }) }); var _e = Object.getOwnPropertyNames(ge), be = !0; function $e(e) { be = e } var we = function (e) { var t; this.value = e, this.dep = new ce, this.vmCount = 0, R(e, "__ob__", this), Array.isArray(e) ? (U ? (t = ge, e.__proto__ = t) : function (e, t, n) { for (var r = 0, i = n.length; r < i; r++) { var o = n[r]; R(e, o, t[o]) } }(e, ge, _e), this.observeArray(e)) : this.walk(e) }; function Ce(e, t) { var n; if (o(e) && !(e instanceof pe)) return y(e, "__ob__") && e.__ob__ instanceof we ? n = e.__ob__ : be && !te() && (Array.isArray(e) || s(e)) && Object.isExtensible(e) && !e._isVue && (n = new we(e)), t && n && n.vmCount++ , n } function xe(e, t, n, r, i) { var o = new ce, a = Object.getOwnPropertyDescriptor(e, t); if (!a || !1 !== a.configurable) { var s = a && a.get, c = a && a.set; s && !c || 2 !== arguments.length || (n = e[t]); var u = !i && Ce(n); Object.defineProperty(e, t, { enumerable: !0, configurable: !0, get: function () { var t = s ? s.call(e) : n; return ce.target && (o.depend(), u && (u.dep.depend(), Array.isArray(t) && function e(t) { for (var n = void 0, r = 0, i = t.length; r < i; r++)(n = t[r]) && n.__ob__ && n.__ob__.dep.depend(), Array.isArray(n) && e(n) }(t))), t }, set: function (t) { var r = s ? s.call(e) : n; t === r || t != t && r != r || s && !c || (c ? c.call(e, t) : n = t, u = !i && Ce(t), o.notify()) } }) } } function ke(e, t, n) { if (Array.isArray(e) && c(t)) return e.length = Math.max(e.length, t), e.splice(t, 1, n), n; if (t in e && !(t in Object.prototype)) return e[t] = n, n; var r = e.__ob__; return e._isVue || r && r.vmCount ? n : r ? (xe(r.value, t, n), r.dep.notify(), n) : (e[t] = n, n) } function Ae(e, t) { if (Array.isArray(e) && c(t)) e.splice(t, 1); else { var n = e.__ob__; e._isVue || n && n.vmCount || y(e, t) && (delete e[t], n && n.dep.notify()) } } we.prototype.walk = function (e) { for (var t = Object.keys(e), n = 0; n < t.length; n++)xe(e, t[n]) }, we.prototype.observeArray = function (e) { for (var t = 0, n = e.length; t < n; t++)Ce(e[t]) }; var Oe = F.optionMergeStrategies; function Se(e, t) { if (!t) return e; for (var n, r, i, o = oe ? Reflect.ownKeys(t) : Object.keys(t), a = 0; a < o.length; a++)"__ob__" !== (n = o[a]) && (r = e[n], i = t[n], y(e, n) ? r !== i && s(r) && s(i) && Se(r, i) : ke(e, n, i)); return e } function Te(e, t, n) { return n ? function () { var r = "function" == typeof t ? t.call(n, n) : t, i = "function" == typeof e ? e.call(n, n) : e; return r ? Se(r, i) : i } : t ? e ? function () { return Se("function" == typeof t ? t.call(this, this) : t, "function" == typeof e ? e.call(this, this) : e) } : t : e } function Ee(e, t) { var n = t ? e ? e.concat(t) : Array.isArray(t) ? t : [t] : e; return n ? function (e) { for (var t = [], n = 0; n < e.length; n++)-1 === t.indexOf(e[n]) && t.push(e[n]); return t }(n) : n } function Ne(e, t, n, r) { var i = Object.create(e || null); return t ? A(i, t) : i } Oe.data = function (e, t, n) { return n ? Te(e, t, n) : t && "function" != typeof t ? e : Te(e, t) }, I.forEach(function (e) { Oe[e] = Ee }), M.forEach(function (e) { Oe[e + "s"] = Ne }), Oe.watch = function (e, t, n, r) { if (e === Y && (e = void 0), t === Y && (t = void 0), !t) return Object.create(e || null); if (!e) return t; var i = {}; for (var o in A(i, e), t) { var a = i[o], s = t[o]; a && !Array.isArray(a) && (a = [a]), i[o] = a ? a.concat(s) : Array.isArray(s) ? s : [s] } return i }, Oe.props = Oe.methods = Oe.inject = Oe.computed = function (e, t, n, r) { if (!e) return t; var i = Object.create(null); return A(i, e), t && A(i, t), i }, Oe.provide = Te; var je = function (e, t) { return void 0 === t ? e : t }; function De(e, t, n) { if ("function" == typeof t && (t = t.options), function (e, t) { var n = e.props; if (n) { var r, i, o = {}; if (Array.isArray(n)) for (r = n.length; r--;)"string" == typeof (i = n[r]) && (o[b(i)] = { type: null }); else if (s(n)) for (var a in n) i = n[a], o[b(a)] = s(i) ? i : { type: i }; e.props = o } }(t), function (e, t) { var n = e.inject; if (n) { var r = e.inject = {}; if (Array.isArray(n)) for (var i = 0; i < n.length; i++)r[n[i]] = { from: n[i] }; else if (s(n)) for (var o in n) { var a = n[o]; r[o] = s(a) ? A({ from: o }, a) : { from: a } } } }(t), function (e) { var t = e.directives; if (t) for (var n in t) { var r = t[n]; "function" == typeof r && (t[n] = { bind: r, update: r }) } }(t), !t._base && (t.extends && (e = De(e, t.extends, n)), t.mixins)) for (var r = 0, i = t.mixins.length; r < i; r++)e = De(e, t.mixins[r], n); var o, a = {}; for (o in e) c(o); for (o in t) y(e, o) || c(o); function c(r) { var i = Oe[r] || je; a[r] = i(e[r], t[r], n, r) } return a } function Le(e, t, n, r) { if ("string" == typeof n) { var i = e[t]; if (y(i, n)) return i[n]; var o = b(n); if (y(i, o)) return i[o]; var a = $(o); return y(i, a) ? i[a] : i[n] || i[o] || i[a] } } function Me(e, t, n, r) { var i = t[e], o = !y(n, e), a = n[e], s = Pe(Boolean, i.type); if (s > -1) if (o && !y(i, "default")) a = !1; else if ("" === a || a === C(e)) { var c = Pe(String, i.type); (c < 0 || s < c) && (a = !0) } if (void 0 === a) { a = function (e, t, n) { if (!y(t, "default")) return; var r = t.default; if (e && e.$options.propsData && void 0 === e.$options.propsData[n] && void 0 !== e._props[n]) return e._props[n]; return "function" == typeof r && "Function" !== Ie(t.type) ? r.call(e) : r }(r, i, e); var u = be; $e(!0), Ce(a), $e(u) } return a } function Ie(e) { var t = e && e.toString().match(/^\s*function (\w+)/); return t ? t[1] : "" } function Fe(e, t) { return Ie(e) === Ie(t) } function Pe(e, t) { if (!Array.isArray(t)) return Fe(t, e) ? 0 : -1; for (var n = 0, r = t.length; n < r; n++)if (Fe(t[n], e)) return n; return -1 } function Re(e, t, n) { le(); try { if (t) for (var r = t; r = r.$parent;) { var i = r.$options.errorCaptured; if (i) for (var o = 0; o < i.length; o++)try { if (!1 === i[o].call(r, e, t, n)) return } catch (e) { Be(e, r, "errorCaptured hook") } } Be(e, t, n) } finally { fe() } } function He(e, t, n, r, i) { var o; try { (o = n ? e.apply(t, n) : e.call(t)) && !o._isVue && u(o) && !o._handled && (o.catch(function (e) { return Re(e, r, i + " (Promise/async)") }), o._handled = !0) } catch (e) { Re(e, r, i) } return o } function Be(e, t, n) { if (F.errorHandler) try { return F.errorHandler.call(null, e, t, n) } catch (t) { t !== e && Ue(t, null, "config.errorHandler") } Ue(e, t, n) } function Ue(e, t, n) { if (!z && !V || "undefined" == typeof console) throw e; console.error(e) } var ze, Ve = !1, Ke = [], Je = !1; function qe() { Je = !1; var e = Ke.slice(0); Ke.length = 0; for (var t = 0; t < e.length; t++)e[t]() } if ("undefined" != typeof Promise && re(Promise)) { var We = Promise.resolve(); ze = function () { We.then(qe), G && setTimeout(S) }, Ve = !0 } else if (q || "undefined" == typeof MutationObserver || !re(MutationObserver) && "[object MutationObserverConstructor]" !== MutationObserver.toString()) ze = "undefined" != typeof setImmediate && re(setImmediate) ? function () { setImmediate(qe) } : function () { setTimeout(qe, 0) }; else { var Ze = 1, Ge = new MutationObserver(qe), Xe = document.createTextNode(String(Ze)); Ge.observe(Xe, { characterData: !0 }), ze = function () { Ze = (Ze + 1) % 2, Xe.data = String(Ze) }, Ve = !0 } function Ye(e, t) { var n; if (Ke.push(function () { if (e) try { e.call(t) } catch (e) { Re(e, t, "nextTick") } else n && n(t) }), Je || (Je = !0, ze()), !e && "undefined" != typeof Promise) return new Promise(function (e) { n = e }) } var Qe = new ie; function et(e) { !function e(t, n) { var r, i; var a = Array.isArray(t); if (!a && !o(t) || Object.isFrozen(t) || t instanceof pe) return; if (t.__ob__) { var s = t.__ob__.dep.id; if (n.has(s)) return; n.add(s) } if (a) for (r = t.length; r--;)e(t[r], n); else for (i = Object.keys(t), r = i.length; r--;)e(t[i[r]], n) }(e, Qe), Qe.clear() } var tt = g(function (e) { var t = "&" === e.charAt(0), n = "~" === (e = t ? e.slice(1) : e).charAt(0), r = "!" === (e = n ? e.slice(1) : e).charAt(0); return { name: e = r ? e.slice(1) : e, once: n, capture: r, passive: t } }); function nt(e, t) { function n() { var e = arguments, r = n.fns; if (!Array.isArray(r)) return He(r, null, arguments, t, "v-on handler"); for (var i = r.slice(), o = 0; o < i.length; o++)He(i[o], null, e, t, "v-on handler") } return n.fns = e, n } function rt(e, n, i, o, a, s) { var c, u, l, f; for (c in e) u = e[c], l = n[c], f = tt(c), t(u) || (t(l) ? (t(u.fns) && (u = e[c] = nt(u, s)), r(f.once) && (u = e[c] = a(f.name, u, f.capture)), i(f.name, u, f.capture, f.passive, f.params)) : u !== l && (l.fns = u, e[c] = l)); for (c in n) t(e[c]) && o((f = tt(c)).name, n[c], f.capture) } function it(e, i, o) { var a; e instanceof pe && (e = e.data.hook || (e.data.hook = {})); var s = e[i]; function c() { o.apply(this, arguments), h(a.fns, c) } t(s) ? a = nt([c]) : n(s.fns) && r(s.merged) ? (a = s).fns.push(c) : a = nt([s, c]), a.merged = !0, e[i] = a } function ot(e, t, r, i, o) { if (n(t)) { if (y(t, r)) return e[r] = t[r], o || delete t[r], !0; if (y(t, i)) return e[r] = t[i], o || delete t[i], !0 } return !1 } function at(e) { return i(e) ? [he(e)] : Array.isArray(e) ? function e(o, a) { var s = []; var c, u, l, f; for (c = 0; c < o.length; c++)t(u = o[c]) || "boolean" == typeof u || (l = s.length - 1, f = s[l], Array.isArray(u) ? u.length > 0 && (st((u = e(u, (a || "") + "_" + c))[0]) && st(f) && (s[l] = he(f.text + u[0].text), u.shift()), s.push.apply(s, u)) : i(u) ? st(f) ? s[l] = he(f.text + u) : "" !== u && s.push(he(u)) : st(u) && st(f) ? s[l] = he(f.text + u.text) : (r(o._isVList) && n(u.tag) && t(u.key) && n(a) && (u.key = "__vlist" + a + "_" + c + "__"), s.push(u))); return s }(e) : void 0 } function st(e) { return n(e) && n(e.text) && !1 === e.isComment } function ct(e, t) { if (e) { for (var n = Object.create(null), r = oe ? Reflect.ownKeys(e) : Object.keys(e), i = 0; i < r.length; i++) { var o = r[i]; if ("__ob__" !== o) { for (var a = e[o].from, s = t; s;) { if (s._provided && y(s._provided, a)) { n[o] = s._provided[a]; break } s = s.$parent } if (!s && "default" in e[o]) { var c = e[o].default; n[o] = "function" == typeof c ? c.call(t) : c } } } return n } } function ut(e, t) { if (!e || !e.length) return {}; for (var n = {}, r = 0, i = e.length; r < i; r++) { var o = e[r], a = o.data; if (a && a.attrs && a.attrs.slot && delete a.attrs.slot, o.context !== t && o.fnContext !== t || !a || null == a.slot) (n.default || (n.default = [])).push(o); else { var s = a.slot, c = n[s] || (n[s] = []); "template" === o.tag ? c.push.apply(c, o.children || []) : c.push(o) } } for (var u in n) n[u].every(lt) && delete n[u]; return n } function lt(e) { return e.isComment && !e.asyncFactory || " " === e.text } function ft(t, n, r) { var i, o = Object.keys(n).length > 0, a = t ? !!t.$stable : !o, s = t && t.$key; if (t) { if (t._normalized) return t._normalized; if (a && r && r !== e && s === r.$key && !o && !r.$hasNormal) return r; for (var c in i = {}, t) t[c] && "$" !== c[0] && (i[c] = pt(n, c, t[c])) } else i = {}; for (var u in n) u in i || (i[u] = dt(n, u)); return t && Object.isExtensible(t) && (t._normalized = i), R(i, "$stable", a), R(i, "$key", s), R(i, "$hasNormal", o), i } function pt(e, t, n) { var r = function () { var e = arguments.length ? n.apply(null, arguments) : n({}); return (e = e && "object" == typeof e && !Array.isArray(e) ? [e] : at(e)) && (0 === e.length || 1 === e.length && e[0].isComment) ? void 0 : e }; return n.proxy && Object.defineProperty(e, t, { get: r, enumerable: !0, configurable: !0 }), r } function dt(e, t) { return function () { return e[t] } } function vt(e, t) { var r, i, a, s, c; if (Array.isArray(e) || "string" == typeof e) for (r = new Array(e.length), i = 0, a = e.length; i < a; i++)r[i] = t(e[i], i); else if ("number" == typeof e) for (r = new Array(e), i = 0; i < e; i++)r[i] = t(i + 1, i); else if (o(e)) if (oe && e[Symbol.iterator]) { r = []; for (var u = e[Symbol.iterator](), l = u.next(); !l.done;)r.push(t(l.value, r.length)), l = u.next() } else for (s = Object.keys(e), r = new Array(s.length), i = 0, a = s.length; i < a; i++)c = s[i], r[i] = t(e[c], c, i); return n(r) || (r = []), r._isVList = !0, r } function ht(e, t, n, r) { var i, o = this.$scopedSlots[e]; o ? (n = n || {}, r && (n = A(A({}, r), n)), i = o(n) || t) : i = this.$slots[e] || t; var a = n && n.slot; return a ? this.$createElement("template", { slot: a }, i) : i } function mt(e) { return Le(this.$options, "filters", e) || E } function yt(e, t) { return Array.isArray(e) ? -1 === e.indexOf(t) : e !== t } function gt(e, t, n, r, i) { var o = F.keyCodes[t] || n; return i && r && !F.keyCodes[t] ? yt(i, r) : o ? yt(o, e) : r ? C(r) !== t : void 0 } function _t(e, t, n, r, i) { if (n) if (o(n)) { var a; Array.isArray(n) && (n = O(n)); var s = function (o) { if ("class" === o || "style" === o || v(o)) a = e; else { var s = e.attrs && e.attrs.type; a = r || F.mustUseProp(t, s, o) ? e.domProps || (e.domProps = {}) : e.attrs || (e.attrs = {}) } var c = b(o), u = C(o); c in a || u in a || (a[o] = n[o], i && ((e.on || (e.on = {}))["update:" + o] = function (e) { n[o] = e })) }; for (var c in n) s(c) } else; return e } function bt(e, t) { var n = this._staticTrees || (this._staticTrees = []), r = n[e]; return r && !t ? r : (wt(r = n[e] = this.$options.staticRenderFns[e].call(this._renderProxy, null, this), "__static__" + e, !1), r) } function $t(e, t, n) { return wt(e, "__once__" + t + (n ? "_" + n : ""), !0), e } function wt(e, t, n) { if (Array.isArray(e)) for (var r = 0; r < e.length; r++)e[r] && "string" != typeof e[r] && Ct(e[r], t + "_" + r, n); else Ct(e, t, n) } function Ct(e, t, n) { e.isStatic = !0, e.key = t, e.isOnce = n } function xt(e, t) { if (t) if (s(t)) { var n = e.on = e.on ? A({}, e.on) : {}; for (var r in t) { var i = n[r], o = t[r]; n[r] = i ? [].concat(i, o) : o } } else; return e } function kt(e, t, n, r) { t = t || { $stable: !n }; for (var i = 0; i < e.length; i++) { var o = e[i]; Array.isArray(o) ? kt(o, t, n) : o && (o.proxy && (o.fn.proxy = !0), t[o.key] = o.fn) } return r && (t.$key = r), t } function At(e, t) { for (var n = 0; n < t.length; n += 2) { var r = t[n]; "string" == typeof r && r && (e[t[n]] = t[n + 1]) } return e } function Ot(e, t) { return "string" == typeof e ? t + e : e } function St(e) { e._o = $t, e._n = f, e._s = l, e._l = vt, e._t = ht, e._q = N, e._i = j, e._m = bt, e._f = mt, e._k = gt, e._b = _t, e._v = he, e._e = ve, e._u = kt, e._g = xt, e._d = At, e._p = Ot } function Tt(t, n, i, o, a) { var s, c = this, u = a.options; y(o, "_uid") ? (s = Object.create(o))._original = o : (s = o, o = o._original); var l = r(u._compiled), f = !l; this.data = t, this.props = n, this.children = i, this.parent = o, this.listeners = t.on || e, this.injections = ct(u.inject, o), this.slots = function () { return c.$slots || ft(t.scopedSlots, c.$slots = ut(i, o)), c.$slots }, Object.defineProperty(this, "scopedSlots", { enumerable: !0, get: function () { return ft(t.scopedSlots, this.slots()) } }), l && (this.$options = u, this.$slots = this.slots(), this.$scopedSlots = ft(t.scopedSlots, this.$slots)), u._scopeId ? this._c = function (e, t, n, r) { var i = Pt(s, e, t, n, r, f); return i && !Array.isArray(i) && (i.fnScopeId = u._scopeId, i.fnContext = o), i } : this._c = function (e, t, n, r) { return Pt(s, e, t, n, r, f) } } function Et(e, t, n, r, i) { var o = me(e); return o.fnContext = n, o.fnOptions = r, t.slot && ((o.data || (o.data = {})).slot = t.slot), o } function Nt(e, t) { for (var n in t) e[b(n)] = t[n] } St(Tt.prototype); var jt = { init: function (e, t) { if (e.componentInstance && !e.componentInstance._isDestroyed && e.data.keepAlive) { var r = e; jt.prepatch(r, r) } else { (e.componentInstance = function (e, t) { var r = { _isComponent: !0, _parentVnode: e, parent: t }, i = e.data.inlineTemplate; n(i) && (r.render = i.render, r.staticRenderFns = i.staticRenderFns); return new e.componentOptions.Ctor(r) }(e, Wt)).$mount(t ? e.elm : void 0, t) } }, prepatch: function (t, n) { var r = n.componentOptions; !function (t, n, r, i, o) { var a = i.data.scopedSlots, s = t.$scopedSlots, c = !!(a && !a.$stable || s !== e && !s.$stable || a && t.$scopedSlots.$key !== a.$key), u = !!(o || t.$options._renderChildren || c); t.$options._parentVnode = i, t.$vnode = i, t._vnode && (t._vnode.parent = i); if (t.$options._renderChildren = o, t.$attrs = i.data.attrs || e, t.$listeners = r || e, n && t.$options.props) { $e(!1); for (var l = t._props, f = t.$options._propKeys || [], p = 0; p < f.length; p++) { var d = f[p], v = t.$options.props; l[d] = Me(d, v, n, t) } $e(!0), t.$options.propsData = n } r = r || e; var h = t.$options._parentListeners; t.$options._parentListeners = r, qt(t, r, h), u && (t.$slots = ut(o, i.context), t.$forceUpdate()) }(n.componentInstance = t.componentInstance, r.propsData, r.listeners, n, r.children) }, insert: function (e) { var t, n = e.context, r = e.componentInstance; r._isMounted || (r._isMounted = !0, Yt(r, "mounted")), e.data.keepAlive && (n._isMounted ? ((t = r)._inactive = !1, en.push(t)) : Xt(r, !0)) }, destroy: function (e) { var t = e.componentInstance; t._isDestroyed || (e.data.keepAlive ? function e(t, n) { if (n && (t._directInactive = !0, Gt(t))) return; if (!t._inactive) { t._inactive = !0; for (var r = 0; r < t.$children.length; r++)e(t.$children[r]); Yt(t, "deactivated") } }(t, !0) : t.$destroy()) } }, Dt = Object.keys(jt); function Lt(i, a, s, c, l) { if (!t(i)) { var f = s.$options._base; if (o(i) && (i = f.extend(i)), "function" == typeof i) { var p; if (t(i.cid) && void 0 === (i = function (e, i) { if (r(e.error) && n(e.errorComp)) return e.errorComp; if (n(e.resolved)) return e.resolved; var a = Ht; a && n(e.owners) && -1 === e.owners.indexOf(a) && e.owners.push(a); if (r(e.loading) && n(e.loadingComp)) return e.loadingComp; if (a && !n(e.owners)) { var s = e.owners = [a], c = !0, l = null, f = null; a.$on("hook:destroyed", function () { return h(s, a) }); var p = function (e) { for (var t = 0, n = s.length; t < n; t++)s[t].$forceUpdate(); e && (s.length = 0, null !== l && (clearTimeout(l), l = null), null !== f && (clearTimeout(f), f = null)) }, d = D(function (t) { e.resolved = Bt(t, i), c ? s.length = 0 : p(!0) }), v = D(function (t) { n(e.errorComp) && (e.error = !0, p(!0)) }), m = e(d, v); return o(m) && (u(m) ? t(e.resolved) && m.then(d, v) : u(m.component) && (m.component.then(d, v), n(m.error) && (e.errorComp = Bt(m.error, i)), n(m.loading) && (e.loadingComp = Bt(m.loading, i), 0 === m.delay ? e.loading = !0 : l = setTimeout(function () { l = null, t(e.resolved) && t(e.error) && (e.loading = !0, p(!1)) }, m.delay || 200)), n(m.timeout) && (f = setTimeout(function () { f = null, t(e.resolved) && v(null) }, m.timeout)))), c = !1, e.loading ? e.loadingComp : e.resolved } }(p = i, f))) return function (e, t, n, r, i) { var o = ve(); return o.asyncFactory = e, o.asyncMeta = { data: t, context: n, children: r, tag: i }, o }(p, a, s, c, l); a = a || {}, $n(i), n(a.model) && function (e, t) { var r = e.model && e.model.prop || "value", i = e.model && e.model.event || "input"; (t.attrs || (t.attrs = {}))[r] = t.model.value; var o = t.on || (t.on = {}), a = o[i], s = t.model.callback; n(a) ? (Array.isArray(a) ? -1 === a.indexOf(s) : a !== s) && (o[i] = [s].concat(a)) : o[i] = s }(i.options, a); var d = function (e, r, i) { var o = r.options.props; if (!t(o)) { var a = {}, s = e.attrs, c = e.props; if (n(s) || n(c)) for (var u in o) { var l = C(u); ot(a, c, u, l, !0) || ot(a, s, u, l, !1) } return a } }(a, i); if (r(i.options.functional)) return function (t, r, i, o, a) { var s = t.options, c = {}, u = s.props; if (n(u)) for (var l in u) c[l] = Me(l, u, r || e); else n(i.attrs) && Nt(c, i.attrs), n(i.props) && Nt(c, i.props); var f = new Tt(i, c, a, o, t), p = s.render.call(null, f._c, f); if (p instanceof pe) return Et(p, i, f.parent, s); if (Array.isArray(p)) { for (var d = at(p) || [], v = new Array(d.length), h = 0; h < d.length; h++)v[h] = Et(d[h], i, f.parent, s); return v } }(i, d, a, s, c); var v = a.on; if (a.on = a.nativeOn, r(i.options.abstract)) { var m = a.slot; a = {}, m && (a.slot = m) } !function (e) { for (var t = e.hook || (e.hook = {}), n = 0; n < Dt.length; n++) { var r = Dt[n], i = t[r], o = jt[r]; i === o || i && i._merged || (t[r] = i ? Mt(o, i) : o) } }(a); var y = i.options.name || l; return new pe("vue-component-" + i.cid + (y ? "-" + y : ""), a, void 0, void 0, void 0, s, { Ctor: i, propsData: d, listeners: v, tag: l, children: c }, p) } } } function Mt(e, t) { var n = function (n, r) { e(n, r), t(n, r) }; return n._merged = !0, n } var It = 1, Ft = 2; function Pt(e, a, s, c, u, l) { return (Array.isArray(s) || i(s)) && (u = c, c = s, s = void 0), r(l) && (u = Ft), function (e, i, a, s, c) { if (n(a) && n(a.__ob__)) return ve(); n(a) && n(a.is) && (i = a.is); if (!i) return ve(); Array.isArray(s) && "function" == typeof s[0] && ((a = a || {}).scopedSlots = { default: s[0] }, s.length = 0); c === Ft ? s = at(s) : c === It && (s = function (e) { for (var t = 0; t < e.length; t++)if (Array.isArray(e[t])) return Array.prototype.concat.apply([], e); return e }(s)); var u, l; if ("string" == typeof i) { var f; l = e.$vnode && e.$vnode.ns || F.getTagNamespace(i), u = F.isReservedTag(i) ? new pe(F.parsePlatformTagName(i), a, s, void 0, void 0, e) : a && a.pre || !n(f = Le(e.$options, "components", i)) ? new pe(i, a, s, void 0, void 0, e) : Lt(f, a, e, s, i) } else u = Lt(i, a, e, s); return Array.isArray(u) ? u : n(u) ? (n(l) && function e(i, o, a) { i.ns = o; "foreignObject" === i.tag && (o = void 0, a = !0); if (n(i.children)) for (var s = 0, c = i.children.length; s < c; s++) { var u = i.children[s]; n(u.tag) && (t(u.ns) || r(a) && "svg" !== u.tag) && e(u, o, a) } }(u, l), n(a) && function (e) { o(e.style) && et(e.style); o(e.class) && et(e.class) }(a), u) : ve() }(e, a, s, c, u) } var Rt, Ht = null; function Bt(e, t) { return (e.__esModule || oe && "Module" === e[Symbol.toStringTag]) && (e = e.default), o(e) ? t.extend(e) : e } function Ut(e) { return e.isComment && e.asyncFactory } function zt(e) { if (Array.isArray(e)) for (var t = 0; t < e.length; t++) { var r = e[t]; if (n(r) && (n(r.componentOptions) || Ut(r))) return r } } function Vt(e, t) { Rt.$on(e, t) } function Kt(e, t) { Rt.$off(e, t) } function Jt(e, t) { var n = Rt; return function r() { null !== t.apply(null, arguments) && n.$off(e, r) } } function qt(e, t, n) { Rt = e, rt(t, n || {}, Vt, Kt, Jt, e), Rt = void 0 } var Wt = null; function Zt(e) { var t = Wt; return Wt = e, function () { Wt = t } } function Gt(e) { for (; e && (e = e.$parent);)if (e._inactive) return !0; return !1 } function Xt(e, t) { if (t) { if (e._directInactive = !1, Gt(e)) return } else if (e._directInactive) return; if (e._inactive || null === e._inactive) { e._inactive = !1; for (var n = 0; n < e.$children.length; n++)Xt(e.$children[n]); Yt(e, "activated") } } function Yt(e, t) { le(); var n = e.$options[t], r = t + " hook"; if (n) for (var i = 0, o = n.length; i < o; i++)He(n[i], e, null, e, r); e._hasHookEvent && e.$emit("hook:" + t), fe() } var Qt = [], en = [], tn = {}, nn = !1, rn = !1, on = 0; var an = 0, sn = Date.now; if (z && !q) { var cn = window.performance; cn && "function" == typeof cn.now && sn() > document.createEvent("Event").timeStamp && (sn = function () { return cn.now() }) } function un() { var e, t; for (an = sn(), rn = !0, Qt.sort(function (e, t) { return e.id - t.id }), on = 0; on < Qt.length; on++)(e = Qt[on]).before && e.before(), t = e.id, tn[t] = null, e.run(); var n = en.slice(), r = Qt.slice(); on = Qt.length = en.length = 0, tn = {}, nn = rn = !1, function (e) { for (var t = 0; t < e.length; t++)e[t]._inactive = !0, Xt(e[t], !0) }(n), function (e) { var t = e.length; for (; t--;) { var n = e[t], r = n.vm; r._watcher === n && r._isMounted && !r._isDestroyed && Yt(r, "updated") } }(r), ne && F.devtools && ne.emit("flush") } var ln = 0, fn = function (e, t, n, r, i) { this.vm = e, i && (e._watcher = this), e._watchers.push(this), r ? (this.deep = !!r.deep, this.user = !!r.user, this.lazy = !!r.lazy, this.sync = !!r.sync, this.before = r.before) : this.deep = this.user = this.lazy = this.sync = !1, this.cb = n, this.id = ++ln, this.active = !0, this.dirty = this.lazy, this.deps = [], this.newDeps = [], this.depIds = new ie, this.newDepIds = new ie, this.expression = "", "function" == typeof t ? this.getter = t : (this.getter = function (e) { if (!H.test(e)) { var t = e.split("."); return function (e) { for (var n = 0; n < t.length; n++) { if (!e) return; e = e[t[n]] } return e } } }(t), this.getter || (this.getter = S)), this.value = this.lazy ? void 0 : this.get() }; fn.prototype.get = function () { var e; le(this); var t = this.vm; try { e = this.getter.call(t, t) } catch (e) { if (!this.user) throw e; Re(e, t, 'getter for watcher "' + this.expression + '"') } finally { this.deep && et(e), fe(), this.cleanupDeps() } return e }, fn.prototype.addDep = function (e) { var t = e.id; this.newDepIds.has(t) || (this.newDepIds.add(t), this.newDeps.push(e), this.depIds.has(t) || e.addSub(this)) }, fn.prototype.cleanupDeps = function () { for (var e = this.deps.length; e--;) { var t = this.deps[e]; this.newDepIds.has(t.id) || t.removeSub(this) } var n = this.depIds; this.depIds = this.newDepIds, this.newDepIds = n, this.newDepIds.clear(), n = this.deps, this.deps = this.newDeps, this.newDeps = n, this.newDeps.length = 0 }, fn.prototype.update = function () { this.lazy ? this.dirty = !0 : this.sync ? this.run() : function (e) { var t = e.id; if (null == tn[t]) { if (tn[t] = !0, rn) { for (var n = Qt.length - 1; n > on && Qt[n].id > e.id;)n--; Qt.splice(n + 1, 0, e) } else Qt.push(e); nn || (nn = !0, Ye(un)) } }(this) }, fn.prototype.run = function () { if (this.active) { var e = this.get(); if (e !== this.value || o(e) || this.deep) { var t = this.value; if (this.value = e, this.user) try { this.cb.call(this.vm, e, t) } catch (e) { Re(e, this.vm, 'callback for watcher "' + this.expression + '"') } else this.cb.call(this.vm, e, t) } } }, fn.prototype.evaluate = function () { this.value = this.get(), this.dirty = !1 }, fn.prototype.depend = function () { for (var e = this.deps.length; e--;)this.deps[e].depend() }, fn.prototype.teardown = function () { if (this.active) { this.vm._isBeingDestroyed || h(this.vm._watchers, this); for (var e = this.deps.length; e--;)this.deps[e].removeSub(this); this.active = !1 } }; var pn = { enumerable: !0, configurable: !0, get: S, set: S }; function dn(e, t, n) { pn.get = function () { return this[t][n] }, pn.set = function (e) { this[t][n] = e }, Object.defineProperty(e, n, pn) } function vn(e) { e._watchers = []; var t = e.$options; t.props && function (e, t) { var n = e.$options.propsData || {}, r = e._props = {}, i = e.$options._propKeys = []; e.$parent && $e(!1); var o = function (o) { i.push(o); var a = Me(o, t, n, e); xe(r, o, a), o in e || dn(e, "_props", o) }; for (var a in t) o(a); $e(!0) }(e, t.props), t.methods && function (e, t) { e.$options.props; for (var n in t) e[n] = "function" != typeof t[n] ? S : x(t[n], e) }(e, t.methods), t.data ? function (e) { var t = e.$options.data; s(t = e._data = "function" == typeof t ? function (e, t) { le(); try { return e.call(t, t) } catch (e) { return Re(e, t, "data()"), {} } finally { fe() } }(t, e) : t || {}) || (t = {}); var n = Object.keys(t), r = e.$options.props, i = (e.$options.methods, n.length); for (; i--;) { var o = n[i]; r && y(r, o) || (a = void 0, 36 !== (a = (o + "").charCodeAt(0)) && 95 !== a && dn(e, "_data", o)) } var a; Ce(t, !0) }(e) : Ce(e._data = {}, !0), t.computed && function (e, t) { var n = e._computedWatchers = Object.create(null), r = te(); for (var i in t) { var o = t[i], a = "function" == typeof o ? o : o.get; r || (n[i] = new fn(e, a || S, S, hn)), i in e || mn(e, i, o) } }(e, t.computed), t.watch && t.watch !== Y && function (e, t) { for (var n in t) { var r = t[n]; if (Array.isArray(r)) for (var i = 0; i < r.length; i++)_n(e, n, r[i]); else _n(e, n, r) } }(e, t.watch) } var hn = { lazy: !0 }; function mn(e, t, n) { var r = !te(); "function" == typeof n ? (pn.get = r ? yn(t) : gn(n), pn.set = S) : (pn.get = n.get ? r && !1 !== n.cache ? yn(t) : gn(n.get) : S, pn.set = n.set || S), Object.defineProperty(e, t, pn) } function yn(e) { return function () { var t = this._computedWatchers && this._computedWatchers[e]; if (t) return t.dirty && t.evaluate(), ce.target && t.depend(), t.value } } function gn(e) { return function () { return e.call(this, this) } } function _n(e, t, n, r) { return s(n) && (r = n, n = n.handler), "string" == typeof n && (n = e[n]), e.$watch(t, n, r) } var bn = 0; function $n(e) { var t = e.options; if (e.super) { var n = $n(e.super); if (n !== e.superOptions) { e.superOptions = n; var r = function (e) { var t, n = e.options, r = e.sealedOptions; for (var i in n) n[i] !== r[i] && (t || (t = {}), t[i] = n[i]); return t }(e); r && A(e.extendOptions, r), (t = e.options = De(n, e.extendOptions)).name && (t.components[t.name] = e) } } return t } function wn(e) { this._init(e) } function Cn(e) { e.cid = 0; var t = 1; e.extend = function (e) { e = e || {}; var n = this, r = n.cid, i = e._Ctor || (e._Ctor = {}); if (i[r]) return i[r]; var o = e.name || n.options.name, a = function (e) { this._init(e) }; return (a.prototype = Object.create(n.prototype)).constructor = a, a.cid = t++ , a.options = De(n.options, e), a.super = n, a.options.props && function (e) { var t = e.options.props; for (var n in t) dn(e.prototype, "_props", n) }(a), a.options.computed && function (e) { var t = e.options.computed; for (var n in t) mn(e.prototype, n, t[n]) }(a), a.extend = n.extend, a.mixin = n.mixin, a.use = n.use, M.forEach(function (e) { a[e] = n[e] }), o && (a.options.components[o] = a), a.superOptions = n.options, a.extendOptions = e, a.sealedOptions = A({}, a.options), i[r] = a, a } } function xn(e) { return e && (e.Ctor.options.name || e.tag) } function kn(e, t) { return Array.isArray(e) ? e.indexOf(t) > -1 : "string" == typeof e ? e.split(",").indexOf(t) > -1 : (n = e, "[object RegExp]" === a.call(n) && e.test(t)); var n } function An(e, t) { var n = e.cache, r = e.keys, i = e._vnode; for (var o in n) { var a = n[o]; if (a) { var s = xn(a.componentOptions); s && !t(s) && On(n, o, r, i) } } } function On(e, t, n, r) { var i = e[t]; !i || r && i.tag === r.tag || i.componentInstance.$destroy(), e[t] = null, h(n, t) } !function (t) { t.prototype._init = function (t) { var n = this; n._uid = bn++ , n._isVue = !0, t && t._isComponent ? function (e, t) { var n = e.$options = Object.create(e.constructor.options), r = t._parentVnode; n.parent = t.parent, n._parentVnode = r; var i = r.componentOptions; n.propsData = i.propsData, n._parentListeners = i.listeners, n._renderChildren = i.children, n._componentTag = i.tag, t.render && (n.render = t.render, n.staticRenderFns = t.staticRenderFns) }(n, t) : n.$options = De($n(n.constructor), t || {}, n), n._renderProxy = n, n._self = n, function (e) { var t = e.$options, n = t.parent; if (n && !t.abstract) { for (; n.$options.abstract && n.$parent;)n = n.$parent; n.$children.push(e) } e.$parent = n, e.$root = n ? n.$root : e, e.$children = [], e.$refs = {}, e._watcher = null, e._inactive = null, e._directInactive = !1, e._isMounted = !1, e._isDestroyed = !1, e._isBeingDestroyed = !1 }(n), function (e) { e._events = Object.create(null), e._hasHookEvent = !1; var t = e.$options._parentListeners; t && qt(e, t) }(n), function (t) { t._vnode = null, t._staticTrees = null; var n = t.$options, r = t.$vnode = n._parentVnode, i = r && r.context; t.$slots = ut(n._renderChildren, i), t.$scopedSlots = e, t._c = function (e, n, r, i) { return Pt(t, e, n, r, i, !1) }, t.$createElement = function (e, n, r, i) { return Pt(t, e, n, r, i, !0) }; var o = r && r.data; xe(t, "$attrs", o && o.attrs || e, null, !0), xe(t, "$listeners", n._parentListeners || e, null, !0) }(n), Yt(n, "beforeCreate"), function (e) { var t = ct(e.$options.inject, e); t && ($e(!1), Object.keys(t).forEach(function (n) { xe(e, n, t[n]) }), $e(!0)) }(n), vn(n), function (e) { var t = e.$options.provide; t && (e._provided = "function" == typeof t ? t.call(e) : t) }(n), Yt(n, "created"), n.$options.el && n.$mount(n.$options.el) } }(wn), function (e) { var t = { get: function () { return this._data } }, n = { get: function () { return this._props } }; Object.defineProperty(e.prototype, "$data", t), Object.defineProperty(e.prototype, "$props", n), e.prototype.$set = ke, e.prototype.$delete = Ae, e.prototype.$watch = function (e, t, n) { if (s(t)) return _n(this, e, t, n); (n = n || {}).user = !0; var r = new fn(this, e, t, n); if (n.immediate) try { t.call(this, r.value) } catch (e) { Re(e, this, 'callback for immediate watcher "' + r.expression + '"') } return function () { r.teardown() } } }(wn), function (e) { var t = /^hook:/; e.prototype.$on = function (e, n) { var r = this; if (Array.isArray(e)) for (var i = 0, o = e.length; i < o; i++)r.$on(e[i], n); else (r._events[e] || (r._events[e] = [])).push(n), t.test(e) && (r._hasHookEvent = !0); return r }, e.prototype.$once = function (e, t) { var n = this; function r() { n.$off(e, r), t.apply(n, arguments) } return r.fn = t, n.$on(e, r), n }, e.prototype.$off = function (e, t) { var n = this; if (!arguments.length) return n._events = Object.create(null), n; if (Array.isArray(e)) { for (var r = 0, i = e.length; r < i; r++)n.$off(e[r], t); return n } var o, a = n._events[e]; if (!a) return n; if (!t) return n._events[e] = null, n; for (var s = a.length; s--;)if ((o = a[s]) === t || o.fn === t) { a.splice(s, 1); break } return n }, e.prototype.$emit = function (e) { var t = this._events[e]; if (t) { t = t.length > 1 ? k(t) : t; for (var n = k(arguments, 1), r = 'event handler for "' + e + '"', i = 0, o = t.length; i < o; i++)He(t[i], this, n, this, r) } return this } }(wn), function (e) { e.prototype._update = function (e, t) { var n = this, r = n.$el, i = n._vnode, o = Zt(n); n._vnode = e, n.$el = i ? n.__patch__(i, e) : n.__patch__(n.$el, e, t, !1), o(), r && (r.__vue__ = null), n.$el && (n.$el.__vue__ = n), n.$vnode && n.$parent && n.$vnode === n.$parent._vnode && (n.$parent.$el = n.$el) }, e.prototype.$forceUpdate = function () { this._watcher && this._watcher.update() }, e.prototype.$destroy = function () { var e = this; if (!e._isBeingDestroyed) { Yt(e, "beforeDestroy"), e._isBeingDestroyed = !0; var t = e.$parent; !t || t._isBeingDestroyed || e.$options.abstract || h(t.$children, e), e._watcher && e._watcher.teardown(); for (var n = e._watchers.length; n--;)e._watchers[n].teardown(); e._data.__ob__ && e._data.__ob__.vmCount-- , e._isDestroyed = !0, e.__patch__(e._vnode, null), Yt(e, "destroyed"), e.$off(), e.$el && (e.$el.__vue__ = null), e.$vnode && (e.$vnode.parent = null) } } }(wn), function (e) { St(e.prototype), e.prototype.$nextTick = function (e) { return Ye(e, this) }, e.prototype._render = function () { var e, t = this, n = t.$options, r = n.render, i = n._parentVnode; i && (t.$scopedSlots = ft(i.data.scopedSlots, t.$slots, t.$scopedSlots)), t.$vnode = i; try { Ht = t, e = r.call(t._renderProxy, t.$createElement) } catch (n) { Re(n, t, "render"), e = t._vnode } finally { Ht = null } return Array.isArray(e) && 1 === e.length && (e = e[0]), e instanceof pe || (e = ve()), e.parent = i, e } }(wn); var Sn = [String, RegExp, Array], Tn = { KeepAlive: { name: "keep-alive", abstract: !0, props: { include: Sn, exclude: Sn, max: [String, Number] }, created: function () { this.cache = Object.create(null), this.keys = [] }, destroyed: function () { for (var e in this.cache) On(this.cache, e, this.keys) }, mounted: function () { var e = this; this.$watch("include", function (t) { An(e, function (e) { return kn(t, e) }) }), this.$watch("exclude", function (t) { An(e, function (e) { return !kn(t, e) }) }) }, render: function () { var e = this.$slots.default, t = zt(e), n = t && t.componentOptions; if (n) { var r = xn(n), i = this.include, o = this.exclude; if (i && (!r || !kn(i, r)) || o && r && kn(o, r)) return t; var a = this.cache, s = this.keys, c = null == t.key ? n.Ctor.cid + (n.tag ? "::" + n.tag : "") : t.key; a[c] ? (t.componentInstance = a[c].componentInstance, h(s, c), s.push(c)) : (a[c] = t, s.push(c), this.max && s.length > parseInt(this.max) && On(a, s[0], s, this._vnode)), t.data.keepAlive = !0 } return t || e && e[0] } } }; !function (e) { var t = { get: function () { return F } }; Object.defineProperty(e, "config", t), e.util = { warn: ae, extend: A, mergeOptions: De, defineReactive: xe }, e.set = ke, e.delete = Ae, e.nextTick = Ye, e.observable = function (e) { return Ce(e), e }, e.options = Object.create(null), M.forEach(function (t) { e.options[t + "s"] = Object.create(null) }), e.options._base = e, A(e.options.components, Tn), function (e) { e.use = function (e) { var t = this._installedPlugins || (this._installedPlugins = []); if (t.indexOf(e) > -1) return this; var n = k(arguments, 1); return n.unshift(this), "function" == typeof e.install ? e.install.apply(e, n) : "function" == typeof e && e.apply(null, n), t.push(e), this } }(e), function (e) { e.mixin = function (e) { return this.options = De(this.options, e), this } }(e), Cn(e), function (e) { M.forEach(function (t) { e[t] = function (e, n) { return n ? ("component" === t && s(n) && (n.name = n.name || e, n = this.options._base.extend(n)), "directive" === t && "function" == typeof n && (n = { bind: n, update: n }), this.options[t + "s"][e] = n, n) : this.options[t + "s"][e] } }) }(e) }(wn), Object.defineProperty(wn.prototype, "$isServer", { get: te }), Object.defineProperty(wn.prototype, "$ssrContext", { get: function () { return this.$vnode && this.$vnode.ssrContext } }), Object.defineProperty(wn, "FunctionalRenderContext", { value: Tt }), wn.version = "2.6.10"; var En = p("style,class"), Nn = p("input,textarea,option,select,progress"), jn = function (e, t, n) { return "value" === n && Nn(e) && "button" !== t || "selected" === n && "option" === e || "checked" === n && "input" === e || "muted" === n && "video" === e }, Dn = p("contenteditable,draggable,spellcheck"), Ln = p("events,caret,typing,plaintext-only"), Mn = function (e, t) { return Hn(t) || "false" === t ? "false" : "contenteditable" === e && Ln(t) ? t : "true" }, In = p("allowfullscreen,async,autofocus,autoplay,checked,compact,controls,declare,default,defaultchecked,defaultmuted,defaultselected,defer,disabled,enabled,formnovalidate,hidden,indeterminate,inert,ismap,itemscope,loop,multiple,muted,nohref,noresize,noshade,novalidate,nowrap,open,pauseonexit,readonly,required,reversed,scoped,seamless,selected,sortable,translate,truespeed,typemustmatch,visible"), Fn = "http://www.w3.org/1999/xlink", Pn = function (e) { return ":" === e.charAt(5) && "xlink" === e.slice(0, 5) }, Rn = function (e) { return Pn(e) ? e.slice(6, e.length) : "" }, Hn = function (e) { return null == e || !1 === e }; function Bn(e) { for (var t = e.data, r = e, i = e; n(i.componentInstance);)(i = i.componentInstance._vnode) && i.data && (t = Un(i.data, t)); for (; n(r = r.parent);)r && r.data && (t = Un(t, r.data)); return function (e, t) { if (n(e) || n(t)) return zn(e, Vn(t)); return "" }(t.staticClass, t.class) } function Un(e, t) { return { staticClass: zn(e.staticClass, t.staticClass), class: n(e.class) ? [e.class, t.class] : t.class } } function zn(e, t) { return e ? t ? e + " " + t : e : t || "" } function Vn(e) { return Array.isArray(e) ? function (e) { for (var t, r = "", i = 0, o = e.length; i < o; i++)n(t = Vn(e[i])) && "" !== t && (r && (r += " "), r += t); return r }(e) : o(e) ? function (e) { var t = ""; for (var n in e) e[n] && (t && (t += " "), t += n); return t }(e) : "string" == typeof e ? e : "" } var Kn = { svg: "http://www.w3.org/2000/svg", math: "http://www.w3.org/1998/Math/MathML" }, Jn = p("html,body,base,head,link,meta,style,title,address,article,aside,footer,header,h1,h2,h3,h4,h5,h6,hgroup,nav,section,div,dd,dl,dt,figcaption,figure,picture,hr,img,li,main,ol,p,pre,ul,a,b,abbr,bdi,bdo,br,cite,code,data,dfn,em,i,kbd,mark,q,rp,rt,rtc,ruby,s,samp,small,span,strong,sub,sup,time,u,var,wbr,area,audio,map,track,video,embed,object,param,source,canvas,script,noscript,del,ins,caption,col,colgroup,table,thead,tbody,td,th,tr,button,datalist,fieldset,form,input,label,legend,meter,optgroup,option,output,progress,select,textarea,details,dialog,menu,menuitem,summary,content,element,shadow,template,blockquote,iframe,tfoot"), qn = p("svg,animate,circle,clippath,cursor,defs,desc,ellipse,filter,font-face,foreignObject,g,glyph,image,line,marker,mask,missing-glyph,path,pattern,polygon,polyline,rect,switch,symbol,text,textpath,tspan,use,view", !0), Wn = function (e) { return Jn(e) || qn(e) }; function Zn(e) { return qn(e) ? "svg" : "math" === e ? "math" : void 0 } var Gn = Object.create(null); var Xn = p("text,number,password,search,email,tel,url"); function Yn(e) { if ("string" == typeof e) { var t = document.querySelector(e); return t || document.createElement("div") } return e } var Qn = Object.freeze({ createElement: function (e, t) { var n = document.createElement(e); return "select" !== e ? n : (t.data && t.data.attrs && void 0 !== t.data.attrs.multiple && n.setAttribute("multiple", "multiple"), n) }, createElementNS: function (e, t) { return document.createElementNS(Kn[e], t) }, createTextNode: function (e) { return document.createTextNode(e) }, createComment: function (e) { return document.createComment(e) }, insertBefore: function (e, t, n) { e.insertBefore(t, n) }, removeChild: function (e, t) { e.removeChild(t) }, appendChild: function (e, t) { e.appendChild(t) }, parentNode: function (e) { return e.parentNode }, nextSibling: function (e) { return e.nextSibling }, tagName: function (e) { return e.tagName }, setTextContent: function (e, t) { e.textContent = t }, setStyleScope: function (e, t) { e.setAttribute(t, "") } }), er = { create: function (e, t) { tr(t) }, update: function (e, t) { e.data.ref !== t.data.ref && (tr(e, !0), tr(t)) }, destroy: function (e) { tr(e, !0) } }; function tr(e, t) { var r = e.data.ref; if (n(r)) { var i = e.context, o = e.componentInstance || e.elm, a = i.$refs; t ? Array.isArray(a[r]) ? h(a[r], o) : a[r] === o && (a[r] = void 0) : e.data.refInFor ? Array.isArray(a[r]) ? a[r].indexOf(o) < 0 && a[r].push(o) : a[r] = [o] : a[r] = o } } var nr = new pe("", {}, []), rr = ["create", "activate", "update", "remove", "destroy"]; function ir(e, i) { return e.key === i.key && (e.tag === i.tag && e.isComment === i.isComment && n(e.data) === n(i.data) && function (e, t) { if ("input" !== e.tag) return !0; var r, i = n(r = e.data) && n(r = r.attrs) && r.type, o = n(r = t.data) && n(r = r.attrs) && r.type; return i === o || Xn(i) && Xn(o) }(e, i) || r(e.isAsyncPlaceholder) && e.asyncFactory === i.asyncFactory && t(i.asyncFactory.error)) } function or(e, t, r) { var i, o, a = {}; for (i = t; i <= r; ++i)n(o = e[i].key) && (a[o] = i); return a } var ar = { create: sr, update: sr, destroy: function (e) { sr(e, nr) } }; function sr(e, t) { (e.data.directives || t.data.directives) && function (e, t) { var n, r, i, o = e === nr, a = t === nr, s = ur(e.data.directives, e.context), c = ur(t.data.directives, t.context), u = [], l = []; for (n in c) r = s[n], i = c[n], r ? (i.oldValue = r.value, i.oldArg = r.arg, fr(i, "update", t, e), i.def && i.def.componentUpdated && l.push(i)) : (fr(i, "bind", t, e), i.def && i.def.inserted && u.push(i)); if (u.length) { var f = function () { for (var n = 0; n < u.length; n++)fr(u[n], "inserted", t, e) }; o ? it(t, "insert", f) : f() } l.length && it(t, "postpatch", function () { for (var n = 0; n < l.length; n++)fr(l[n], "componentUpdated", t, e) }); if (!o) for (n in s) c[n] || fr(s[n], "unbind", e, e, a) }(e, t) } var cr = Object.create(null); function ur(e, t) { var n, r, i = Object.create(null); if (!e) return i; for (n = 0; n < e.length; n++)(r = e[n]).modifiers || (r.modifiers = cr), i[lr(r)] = r, r.def = Le(t.$options, "directives", r.name); return i } function lr(e) { return e.rawName || e.name + "." + Object.keys(e.modifiers || {}).join(".") } function fr(e, t, n, r, i) { var o = e.def && e.def[t]; if (o) try { o(n.elm, e, n, r, i) } catch (r) { Re(r, n.context, "directive " + e.name + " " + t + " hook") } } var pr = [er, ar]; function dr(e, r) { var i = r.componentOptions; if (!(n(i) && !1 === i.Ctor.options.inheritAttrs || t(e.data.attrs) && t(r.data.attrs))) { var o, a, s = r.elm, c = e.data.attrs || {}, u = r.data.attrs || {}; for (o in n(u.__ob__) && (u = r.data.attrs = A({}, u)), u) a = u[o], c[o] !== a && vr(s, o, a); for (o in (q || Z) && u.value !== c.value && vr(s, "value", u.value), c) t(u[o]) && (Pn(o) ? s.removeAttributeNS(Fn, Rn(o)) : Dn(o) || s.removeAttribute(o)) } } function vr(e, t, n) { e.tagName.indexOf("-") > -1 ? hr(e, t, n) : In(t) ? Hn(n) ? e.removeAttribute(t) : (n = "allowfullscreen" === t && "EMBED" === e.tagName ? "true" : t, e.setAttribute(t, n)) : Dn(t) ? e.setAttribute(t, Mn(t, n)) : Pn(t) ? Hn(n) ? e.removeAttributeNS(Fn, Rn(t)) : e.setAttributeNS(Fn, t, n) : hr(e, t, n) } function hr(e, t, n) { if (Hn(n)) e.removeAttribute(t); else { if (q && !W && "TEXTAREA" === e.tagName && "placeholder" === t && "" !== n && !e.__ieph) { var r = function (t) { t.stopImmediatePropagation(), e.removeEventListener("input", r) }; e.addEventListener("input", r), e.__ieph = !0 } e.setAttribute(t, n) } } var mr = { create: dr, update: dr }; function yr(e, r) { var i = r.elm, o = r.data, a = e.data; if (!(t(o.staticClass) && t(o.class) && (t(a) || t(a.staticClass) && t(a.class)))) { var s = Bn(r), c = i._transitionClasses; n(c) && (s = zn(s, Vn(c))), s !== i._prevClass && (i.setAttribute("class", s), i._prevClass = s) } } var gr, _r, br, $r, wr, Cr, xr = { create: yr, update: yr }, kr = /[\w).+\-_$\]]/; function Ar(e) { var t, n, r, i, o, a = !1, s = !1, c = !1, u = !1, l = 0, f = 0, p = 0, d = 0; for (r = 0; r < e.length; r++)if (n = t, t = e.charCodeAt(r), a) 39 === t && 92 !== n && (a = !1); else if (s) 34 === t && 92 !== n && (s = !1); else if (c) 96 === t && 92 !== n && (c = !1); else if (u) 47 === t && 92 !== n && (u = !1); else if (124 !== t || 124 === e.charCodeAt(r + 1) || 124 === e.charCodeAt(r - 1) || l || f || p) { switch (t) { case 34: s = !0; break; case 39: a = !0; break; case 96: c = !0; break; case 40: p++; break; case 41: p--; break; case 91: f++; break; case 93: f--; break; case 123: l++; break; case 125: l-- }if (47 === t) { for (var v = r - 1, h = void 0; v >= 0 && " " === (h = e.charAt(v)); v--); h && kr.test(h) || (u = !0) } } else void 0 === i ? (d = r + 1, i = e.slice(0, r).trim()) : m(); function m() { (o || (o = [])).push(e.slice(d, r).trim()), d = r + 1 } if (void 0 === i ? i = e.slice(0, r).trim() : 0 !== d && m(), o) for (r = 0; r < o.length; r++)i = Or(i, o[r]); return i } function Or(e, t) { var n = t.indexOf("("); if (n < 0) return '_f("' + t + '")(' + e + ")"; var r = t.slice(0, n), i = t.slice(n + 1); return '_f("' + r + '")(' + e + (")" !== i ? "," + i : i) } function Sr(e, t) { console.error("[Vue compiler]: " + e) } function Tr(e, t) { return e ? e.map(function (e) { return e[t] }).filter(function (e) { return e }) : [] } function Er(e, t, n, r, i) { (e.props || (e.props = [])).push(Rr({ name: t, value: n, dynamic: i }, r)), e.plain = !1 } function Nr(e, t, n, r, i) { (i ? e.dynamicAttrs || (e.dynamicAttrs = []) : e.attrs || (e.attrs = [])).push(Rr({ name: t, value: n, dynamic: i }, r)), e.plain = !1 } function jr(e, t, n, r) { e.attrsMap[t] = n, e.attrsList.push(Rr({ name: t, value: n }, r)) } function Dr(e, t, n, r, i, o, a, s) { (e.directives || (e.directives = [])).push(Rr({ name: t, rawName: n, value: r, arg: i, isDynamicArg: o, modifiers: a }, s)), e.plain = !1 } function Lr(e, t, n) { return n ? "_p(" + t + ',"' + e + '")' : e + t } function Mr(t, n, r, i, o, a, s, c) { var u; (i = i || e).right ? c ? n = "(" + n + ")==='click'?'contextmenu':(" + n + ")" : "click" === n && (n = "contextmenu", delete i.right) : i.middle && (c ? n = "(" + n + ")==='click'?'mouseup':(" + n + ")" : "click" === n && (n = "mouseup")), i.capture && (delete i.capture, n = Lr("!", n, c)), i.once && (delete i.once, n = Lr("~", n, c)), i.passive && (delete i.passive, n = Lr("&", n, c)), i.native ? (delete i.native, u = t.nativeEvents || (t.nativeEvents = {})) : u = t.events || (t.events = {}); var l = Rr({ value: r.trim(), dynamic: c }, s); i !== e && (l.modifiers = i); var f = u[n]; Array.isArray(f) ? o ? f.unshift(l) : f.push(l) : u[n] = f ? o ? [l, f] : [f, l] : l, t.plain = !1 } function Ir(e, t, n) { var r = Fr(e, ":" + t) || Fr(e, "v-bind:" + t); if (null != r) return Ar(r); if (!1 !== n) { var i = Fr(e, t); if (null != i) return JSON.stringify(i) } } function Fr(e, t, n) { var r; if (null != (r = e.attrsMap[t])) for (var i = e.attrsList, o = 0, a = i.length; o < a; o++)if (i[o].name === t) { i.splice(o, 1); break } return n && delete e.attrsMap[t], r } function Pr(e, t) { for (var n = e.attrsList, r = 0, i = n.length; r < i; r++) { var o = n[r]; if (t.test(o.name)) return n.splice(r, 1), o } } function Rr(e, t) { return t && (null != t.start && (e.start = t.start), null != t.end && (e.end = t.end)), e } function Hr(e, t, n) { var r = n || {}, i = r.number, o = "$$v"; r.trim && (o = "(typeof $$v === 'string'? $$v.trim(): $$v)"), i && (o = "_n(" + o + ")"); var a = Br(t, o); e.model = { value: "(" + t + ")", expression: JSON.stringify(t), callback: "function ($$v) {" + a + "}" } } function Br(e, t) { var n = function (e) { if (e = e.trim(), gr = e.length, e.indexOf("[") < 0 || e.lastIndexOf("]") < gr - 1) return ($r = e.lastIndexOf(".")) > -1 ? { exp: e.slice(0, $r), key: '"' + e.slice($r + 1) + '"' } : { exp: e, key: null }; _r = e, $r = wr = Cr = 0; for (; !zr();)Vr(br = Ur()) ? Jr(br) : 91 === br && Kr(br); return { exp: e.slice(0, wr), key: e.slice(wr + 1, Cr) } }(e); return null === n.key ? e + "=" + t : "$set(" + n.exp + ", " + n.key + ", " + t + ")" } function Ur() { return _r.charCodeAt(++$r) } function zr() { return $r >= gr } function Vr(e) { return 34 === e || 39 === e } function Kr(e) { var t = 1; for (wr = $r; !zr();)if (Vr(e = Ur())) Jr(e); else if (91 === e && t++ , 93 === e && t-- , 0 === t) { Cr = $r; break } } function Jr(e) { for (var t = e; !zr() && (e = Ur()) !== t;); } var qr, Wr = "__r", Zr = "__c"; function Gr(e, t, n) { var r = qr; return function i() { null !== t.apply(null, arguments) && Qr(e, i, n, r) } } var Xr = Ve && !(X && Number(X[1]) <= 53); function Yr(e, t, n, r) { if (Xr) { var i = an, o = t; t = o._wrapper = function (e) { if (e.target === e.currentTarget || e.timeStamp >= i || e.timeStamp <= 0 || e.target.ownerDocument !== document) return o.apply(this, arguments) } } qr.addEventListener(e, t, Q ? { capture: n, passive: r } : n) } function Qr(e, t, n, r) { (r || qr).removeEventListener(e, t._wrapper || t, n) } function ei(e, r) { if (!t(e.data.on) || !t(r.data.on)) { var i = r.data.on || {}, o = e.data.on || {}; qr = r.elm, function (e) { if (n(e[Wr])) { var t = q ? "change" : "input"; e[t] = [].concat(e[Wr], e[t] || []), delete e[Wr] } n(e[Zr]) && (e.change = [].concat(e[Zr], e.change || []), delete e[Zr]) }(i), rt(i, o, Yr, Qr, Gr, r.context), qr = void 0 } } var ti, ni = { create: ei, update: ei }; function ri(e, r) { if (!t(e.data.domProps) || !t(r.data.domProps)) { var i, o, a = r.elm, s = e.data.domProps || {}, c = r.data.domProps || {}; for (i in n(c.__ob__) && (c = r.data.domProps = A({}, c)), s) i in c || (a[i] = ""); for (i in c) { if (o = c[i], "textContent" === i || "innerHTML" === i) { if (r.children && (r.children.length = 0), o === s[i]) continue; 1 === a.childNodes.length && a.removeChild(a.childNodes[0]) } if ("value" === i && "PROGRESS" !== a.tagName) { a._value = o; var u = t(o) ? "" : String(o); ii(a, u) && (a.value = u) } else if ("innerHTML" === i && qn(a.tagName) && t(a.innerHTML)) { (ti = ti || document.createElement("div")).innerHTML = "<svg>" + o + "</svg>"; for (var l = ti.firstChild; a.firstChild;)a.removeChild(a.firstChild); for (; l.firstChild;)a.appendChild(l.firstChild) } else if (o !== s[i]) try { a[i] = o } catch (e) { } } } } function ii(e, t) { return !e.composing && ("OPTION" === e.tagName || function (e, t) { var n = !0; try { n = document.activeElement !== e } catch (e) { } return n && e.value !== t }(e, t) || function (e, t) { var r = e.value, i = e._vModifiers; if (n(i)) { if (i.number) return f(r) !== f(t); if (i.trim) return r.trim() !== t.trim() } return r !== t }(e, t)) } var oi = { create: ri, update: ri }, ai = g(function (e) { var t = {}, n = /:(.+)/; return e.split(/;(?![^(]*\))/g).forEach(function (e) { if (e) { var r = e.split(n); r.length > 1 && (t[r[0].trim()] = r[1].trim()) } }), t }); function si(e) { var t = ci(e.style); return e.staticStyle ? A(e.staticStyle, t) : t } function ci(e) { return Array.isArray(e) ? O(e) : "string" == typeof e ? ai(e) : e } var ui, li = /^--/, fi = /\s*!important$/, pi = function (e, t, n) { if (li.test(t)) e.style.setProperty(t, n); else if (fi.test(n)) e.style.setProperty(C(t), n.replace(fi, ""), "important"); else { var r = vi(t); if (Array.isArray(n)) for (var i = 0, o = n.length; i < o; i++)e.style[r] = n[i]; else e.style[r] = n } }, di = ["Webkit", "Moz", "ms"], vi = g(function (e) { if (ui = ui || document.createElement("div").style, "filter" !== (e = b(e)) && e in ui) return e; for (var t = e.charAt(0).toUpperCase() + e.slice(1), n = 0; n < di.length; n++) { var r = di[n] + t; if (r in ui) return r } }); function hi(e, r) { var i = r.data, o = e.data; if (!(t(i.staticStyle) && t(i.style) && t(o.staticStyle) && t(o.style))) { var a, s, c = r.elm, u = o.staticStyle, l = o.normalizedStyle || o.style || {}, f = u || l, p = ci(r.data.style) || {}; r.data.normalizedStyle = n(p.__ob__) ? A({}, p) : p; var d = function (e, t) { var n, r = {}; if (t) for (var i = e; i.componentInstance;)(i = i.componentInstance._vnode) && i.data && (n = si(i.data)) && A(r, n); (n = si(e.data)) && A(r, n); for (var o = e; o = o.parent;)o.data && (n = si(o.data)) && A(r, n); return r }(r, !0); for (s in f) t(d[s]) && pi(c, s, ""); for (s in d) (a = d[s]) !== f[s] && pi(c, s, null == a ? "" : a) } } var mi = { create: hi, update: hi }, yi = /\s+/; function gi(e, t) { if (t && (t = t.trim())) if (e.classList) t.indexOf(" ") > -1 ? t.split(yi).forEach(function (t) { return e.classList.add(t) }) : e.classList.add(t); else { var n = " " + (e.getAttribute("class") || "") + " "; n.indexOf(" " + t + " ") < 0 && e.setAttribute("class", (n + t).trim()) } } function _i(e, t) { if (t && (t = t.trim())) if (e.classList) t.indexOf(" ") > -1 ? t.split(yi).forEach(function (t) { return e.classList.remove(t) }) : e.classList.remove(t), e.classList.length || e.removeAttribute("class"); else { for (var n = " " + (e.getAttribute("class") || "") + " ", r = " " + t + " "; n.indexOf(r) >= 0;)n = n.replace(r, " "); (n = n.trim()) ? e.setAttribute("class", n) : e.removeAttribute("class") } } function bi(e) { if (e) { if ("object" == typeof e) { var t = {}; return !1 !== e.css && A(t, $i(e.name || "v")), A(t, e), t } return "string" == typeof e ? $i(e) : void 0 } } var $i = g(function (e) { return { enterClass: e + "-enter", enterToClass: e + "-enter-to", enterActiveClass: e + "-enter-active", leaveClass: e + "-leave", leaveToClass: e + "-leave-to", leaveActiveClass: e + "-leave-active" } }), wi = z && !W, Ci = "transition", xi = "animation", ki = "transition", Ai = "transitionend", Oi = "animation", Si = "animationend"; wi && (void 0 === window.ontransitionend && void 0 !== window.onwebkittransitionend && (ki = "WebkitTransition", Ai = "webkitTransitionEnd"), void 0 === window.onanimationend && void 0 !== window.onwebkitanimationend && (Oi = "WebkitAnimation", Si = "webkitAnimationEnd")); var Ti = z ? window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : setTimeout : function (e) { return e() }; function Ei(e) { Ti(function () { Ti(e) }) } function Ni(e, t) { var n = e._transitionClasses || (e._transitionClasses = []); n.indexOf(t) < 0 && (n.push(t), gi(e, t)) } function ji(e, t) { e._transitionClasses && h(e._transitionClasses, t), _i(e, t) } function Di(e, t, n) { var r = Mi(e, t), i = r.type, o = r.timeout, a = r.propCount; if (!i) return n(); var s = i === Ci ? Ai : Si, c = 0, u = function () { e.removeEventListener(s, l), n() }, l = function (t) { t.target === e && ++c >= a && u() }; setTimeout(function () { c < a && u() }, o + 1), e.addEventListener(s, l) } var Li = /\b(transform|all)(,|$)/; function Mi(e, t) { var n, r = window.getComputedStyle(e), i = (r[ki + "Delay"] || "").split(", "), o = (r[ki + "Duration"] || "").split(", "), a = Ii(i, o), s = (r[Oi + "Delay"] || "").split(", "), c = (r[Oi + "Duration"] || "").split(", "), u = Ii(s, c), l = 0, f = 0; return t === Ci ? a > 0 && (n = Ci, l = a, f = o.length) : t === xi ? u > 0 && (n = xi, l = u, f = c.length) : f = (n = (l = Math.max(a, u)) > 0 ? a > u ? Ci : xi : null) ? n === Ci ? o.length : c.length : 0, { type: n, timeout: l, propCount: f, hasTransform: n === Ci && Li.test(r[ki + "Property"]) } } function Ii(e, t) { for (; e.length < t.length;)e = e.concat(e); return Math.max.apply(null, t.map(function (t, n) { return Fi(t) + Fi(e[n]) })) } function Fi(e) { return 1e3 * Number(e.slice(0, -1).replace(",", ".")) } function Pi(e, r) { var i = e.elm; n(i._leaveCb) && (i._leaveCb.cancelled = !0, i._leaveCb()); var a = bi(e.data.transition); if (!t(a) && !n(i._enterCb) && 1 === i.nodeType) { for (var s = a.css, c = a.type, u = a.enterClass, l = a.enterToClass, p = a.enterActiveClass, d = a.appearClass, v = a.appearToClass, h = a.appearActiveClass, m = a.beforeEnter, y = a.enter, g = a.afterEnter, _ = a.enterCancelled, b = a.beforeAppear, $ = a.appear, w = a.afterAppear, C = a.appearCancelled, x = a.duration, k = Wt, A = Wt.$vnode; A && A.parent;)k = A.context, A = A.parent; var O = !k._isMounted || !e.isRootInsert; if (!O || $ || "" === $) { var S = O && d ? d : u, T = O && h ? h : p, E = O && v ? v : l, N = O && b || m, j = O && "function" == typeof $ ? $ : y, L = O && w || g, M = O && C || _, I = f(o(x) ? x.enter : x), F = !1 !== s && !W, P = Bi(j), R = i._enterCb = D(function () { F && (ji(i, E), ji(i, T)), R.cancelled ? (F && ji(i, S), M && M(i)) : L && L(i), i._enterCb = null }); e.data.show || it(e, "insert", function () { var t = i.parentNode, n = t && t._pending && t._pending[e.key]; n && n.tag === e.tag && n.elm._leaveCb && n.elm._leaveCb(), j && j(i, R) }), N && N(i), F && (Ni(i, S), Ni(i, T), Ei(function () { ji(i, S), R.cancelled || (Ni(i, E), P || (Hi(I) ? setTimeout(R, I) : Di(i, c, R))) })), e.data.show && (r && r(), j && j(i, R)), F || P || R() } } } function Ri(e, r) { var i = e.elm; n(i._enterCb) && (i._enterCb.cancelled = !0, i._enterCb()); var a = bi(e.data.transition); if (t(a) || 1 !== i.nodeType) return r(); if (!n(i._leaveCb)) { var s = a.css, c = a.type, u = a.leaveClass, l = a.leaveToClass, p = a.leaveActiveClass, d = a.beforeLeave, v = a.leave, h = a.afterLeave, m = a.leaveCancelled, y = a.delayLeave, g = a.duration, _ = !1 !== s && !W, b = Bi(v), $ = f(o(g) ? g.leave : g), w = i._leaveCb = D(function () { i.parentNode && i.parentNode._pending && (i.parentNode._pending[e.key] = null), _ && (ji(i, l), ji(i, p)), w.cancelled ? (_ && ji(i, u), m && m(i)) : (r(), h && h(i)), i._leaveCb = null }); y ? y(C) : C() } function C() { w.cancelled || (!e.data.show && i.parentNode && ((i.parentNode._pending || (i.parentNode._pending = {}))[e.key] = e), d && d(i), _ && (Ni(i, u), Ni(i, p), Ei(function () { ji(i, u), w.cancelled || (Ni(i, l), b || (Hi($) ? setTimeout(w, $) : Di(i, c, w))) })), v && v(i, w), _ || b || w()) } } function Hi(e) { return "number" == typeof e && !isNaN(e) } function Bi(e) { if (t(e)) return !1; var r = e.fns; return n(r) ? Bi(Array.isArray(r) ? r[0] : r) : (e._length || e.length) > 1 } function Ui(e, t) { !0 !== t.data.show && Pi(t) } var zi = function (e) { var o, a, s = {}, c = e.modules, u = e.nodeOps; for (o = 0; o < rr.length; ++o)for (s[rr[o]] = [], a = 0; a < c.length; ++a)n(c[a][rr[o]]) && s[rr[o]].push(c[a][rr[o]]); function l(e) { var t = u.parentNode(e); n(t) && u.removeChild(t, e) } function f(e, t, i, o, a, c, l) { if (n(e.elm) && n(c) && (e = c[l] = me(e)), e.isRootInsert = !a, !function (e, t, i, o) { var a = e.data; if (n(a)) { var c = n(e.componentInstance) && a.keepAlive; if (n(a = a.hook) && n(a = a.init) && a(e, !1), n(e.componentInstance)) return d(e, t), v(i, e.elm, o), r(c) && function (e, t, r, i) { for (var o, a = e; a.componentInstance;)if (a = a.componentInstance._vnode, n(o = a.data) && n(o = o.transition)) { for (o = 0; o < s.activate.length; ++o)s.activate[o](nr, a); t.push(a); break } v(r, e.elm, i) }(e, t, i, o), !0 } }(e, t, i, o)) { var f = e.data, p = e.children, m = e.tag; n(m) ? (e.elm = e.ns ? u.createElementNS(e.ns, m) : u.createElement(m, e), g(e), h(e, p, t), n(f) && y(e, t), v(i, e.elm, o)) : r(e.isComment) ? (e.elm = u.createComment(e.text), v(i, e.elm, o)) : (e.elm = u.createTextNode(e.text), v(i, e.elm, o)) } } function d(e, t) { n(e.data.pendingInsert) && (t.push.apply(t, e.data.pendingInsert), e.data.pendingInsert = null), e.elm = e.componentInstance.$el, m(e) ? (y(e, t), g(e)) : (tr(e), t.push(e)) } function v(e, t, r) { n(e) && (n(r) ? u.parentNode(r) === e && u.insertBefore(e, t, r) : u.appendChild(e, t)) } function h(e, t, n) { if (Array.isArray(t)) for (var r = 0; r < t.length; ++r)f(t[r], n, e.elm, null, !0, t, r); else i(e.text) && u.appendChild(e.elm, u.createTextNode(String(e.text))) } function m(e) { for (; e.componentInstance;)e = e.componentInstance._vnode; return n(e.tag) } function y(e, t) { for (var r = 0; r < s.create.length; ++r)s.create[r](nr, e); n(o = e.data.hook) && (n(o.create) && o.create(nr, e), n(o.insert) && t.push(e)) } function g(e) { var t; if (n(t = e.fnScopeId)) u.setStyleScope(e.elm, t); else for (var r = e; r;)n(t = r.context) && n(t = t.$options._scopeId) && u.setStyleScope(e.elm, t), r = r.parent; n(t = Wt) && t !== e.context && t !== e.fnContext && n(t = t.$options._scopeId) && u.setStyleScope(e.elm, t) } function _(e, t, n, r, i, o) { for (; r <= i; ++r)f(n[r], o, e, t, !1, n, r) } function b(e) { var t, r, i = e.data; if (n(i)) for (n(t = i.hook) && n(t = t.destroy) && t(e), t = 0; t < s.destroy.length; ++t)s.destroy[t](e); if (n(t = e.children)) for (r = 0; r < e.children.length; ++r)b(e.children[r]) } function $(e, t, r, i) { for (; r <= i; ++r) { var o = t[r]; n(o) && (n(o.tag) ? (w(o), b(o)) : l(o.elm)) } } function w(e, t) { if (n(t) || n(e.data)) { var r, i = s.remove.length + 1; for (n(t) ? t.listeners += i : t = function (e, t) { function n() { 0 == --n.listeners && l(e) } return n.listeners = t, n }(e.elm, i), n(r = e.componentInstance) && n(r = r._vnode) && n(r.data) && w(r, t), r = 0; r < s.remove.length; ++r)s.remove[r](e, t); n(r = e.data.hook) && n(r = r.remove) ? r(e, t) : t() } else l(e.elm) } function C(e, t, r, i) { for (var o = r; o < i; o++) { var a = t[o]; if (n(a) && ir(e, a)) return o } } function x(e, i, o, a, c, l) { if (e !== i) { n(i.elm) && n(a) && (i = a[c] = me(i)); var p = i.elm = e.elm; if (r(e.isAsyncPlaceholder)) n(i.asyncFactory.resolved) ? O(e.elm, i, o) : i.isAsyncPlaceholder = !0; else if (r(i.isStatic) && r(e.isStatic) && i.key === e.key && (r(i.isCloned) || r(i.isOnce))) i.componentInstance = e.componentInstance; else { var d, v = i.data; n(v) && n(d = v.hook) && n(d = d.prepatch) && d(e, i); var h = e.children, y = i.children; if (n(v) && m(i)) { for (d = 0; d < s.update.length; ++d)s.update[d](e, i); n(d = v.hook) && n(d = d.update) && d(e, i) } t(i.text) ? n(h) && n(y) ? h !== y && function (e, r, i, o, a) { for (var s, c, l, p = 0, d = 0, v = r.length - 1, h = r[0], m = r[v], y = i.length - 1, g = i[0], b = i[y], w = !a; p <= v && d <= y;)t(h) ? h = r[++p] : t(m) ? m = r[--v] : ir(h, g) ? (x(h, g, o, i, d), h = r[++p], g = i[++d]) : ir(m, b) ? (x(m, b, o, i, y), m = r[--v], b = i[--y]) : ir(h, b) ? (x(h, b, o, i, y), w && u.insertBefore(e, h.elm, u.nextSibling(m.elm)), h = r[++p], b = i[--y]) : ir(m, g) ? (x(m, g, o, i, d), w && u.insertBefore(e, m.elm, h.elm), m = r[--v], g = i[++d]) : (t(s) && (s = or(r, p, v)), t(c = n(g.key) ? s[g.key] : C(g, r, p, v)) ? f(g, o, e, h.elm, !1, i, d) : ir(l = r[c], g) ? (x(l, g, o, i, d), r[c] = void 0, w && u.insertBefore(e, l.elm, h.elm)) : f(g, o, e, h.elm, !1, i, d), g = i[++d]); p > v ? _(e, t(i[y + 1]) ? null : i[y + 1].elm, i, d, y, o) : d > y && $(0, r, p, v) }(p, h, y, o, l) : n(y) ? (n(e.text) && u.setTextContent(p, ""), _(p, null, y, 0, y.length - 1, o)) : n(h) ? $(0, h, 0, h.length - 1) : n(e.text) && u.setTextContent(p, "") : e.text !== i.text && u.setTextContent(p, i.text), n(v) && n(d = v.hook) && n(d = d.postpatch) && d(e, i) } } } function k(e, t, i) { if (r(i) && n(e.parent)) e.parent.data.pendingInsert = t; else for (var o = 0; o < t.length; ++o)t[o].data.hook.insert(t[o]) } var A = p("attrs,class,staticClass,staticStyle,key"); function O(e, t, i, o) { var a, s = t.tag, c = t.data, u = t.children; if (o = o || c && c.pre, t.elm = e, r(t.isComment) && n(t.asyncFactory)) return t.isAsyncPlaceholder = !0, !0; if (n(c) && (n(a = c.hook) && n(a = a.init) && a(t, !0), n(a = t.componentInstance))) return d(t, i), !0; if (n(s)) { if (n(u)) if (e.hasChildNodes()) if (n(a = c) && n(a = a.domProps) && n(a = a.innerHTML)) { if (a !== e.innerHTML) return !1 } else { for (var l = !0, f = e.firstChild, p = 0; p < u.length; p++) { if (!f || !O(f, u[p], i, o)) { l = !1; break } f = f.nextSibling } if (!l || f) return !1 } else h(t, u, i); if (n(c)) { var v = !1; for (var m in c) if (!A(m)) { v = !0, y(t, i); break } !v && c.class && et(c.class) } } else e.data !== t.text && (e.data = t.text); return !0 } return function (e, i, o, a) { if (!t(i)) { var c, l = !1, p = []; if (t(e)) l = !0, f(i, p); else { var d = n(e.nodeType); if (!d && ir(e, i)) x(e, i, p, null, null, a); else { if (d) { if (1 === e.nodeType && e.hasAttribute(L) && (e.removeAttribute(L), o = !0), r(o) && O(e, i, p)) return k(i, p, !0), e; c = e, e = new pe(u.tagName(c).toLowerCase(), {}, [], void 0, c) } var v = e.elm, h = u.parentNode(v); if (f(i, p, v._leaveCb ? null : h, u.nextSibling(v)), n(i.parent)) for (var y = i.parent, g = m(i); y;) { for (var _ = 0; _ < s.destroy.length; ++_)s.destroy[_](y); if (y.elm = i.elm, g) { for (var w = 0; w < s.create.length; ++w)s.create[w](nr, y); var C = y.data.hook.insert; if (C.merged) for (var A = 1; A < C.fns.length; A++)C.fns[A]() } else tr(y); y = y.parent } n(h) ? $(0, [e], 0, 0) : n(e.tag) && b(e) } } return k(i, p, l), i.elm } n(e) && b(e) } }({ nodeOps: Qn, modules: [mr, xr, ni, oi, mi, z ? { create: Ui, activate: Ui, remove: function (e, t) { !0 !== e.data.show ? Ri(e, t) : t() } } : {}].concat(pr) }); W && document.addEventListener("selectionchange", function () { var e = document.activeElement; e && e.vmodel && Xi(e, "input") }); var Vi = { inserted: function (e, t, n, r) { "select" === n.tag ? (r.elm && !r.elm._vOptions ? it(n, "postpatch", function () { Vi.componentUpdated(e, t, n) }) : Ki(e, t, n.context), e._vOptions = [].map.call(e.options, Wi)) : ("textarea" === n.tag || Xn(e.type)) && (e._vModifiers = t.modifiers, t.modifiers.lazy || (e.addEventListener("compositionstart", Zi), e.addEventListener("compositionend", Gi), e.addEventListener("change", Gi), W && (e.vmodel = !0))) }, componentUpdated: function (e, t, n) { if ("select" === n.tag) { Ki(e, t, n.context); var r = e._vOptions, i = e._vOptions = [].map.call(e.options, Wi); if (i.some(function (e, t) { return !N(e, r[t]) })) (e.multiple ? t.value.some(function (e) { return qi(e, i) }) : t.value !== t.oldValue && qi(t.value, i)) && Xi(e, "change") } } }; function Ki(e, t, n) { Ji(e, t, n), (q || Z) && setTimeout(function () { Ji(e, t, n) }, 0) } function Ji(e, t, n) { var r = t.value, i = e.multiple; if (!i || Array.isArray(r)) { for (var o, a, s = 0, c = e.options.length; s < c; s++)if (a = e.options[s], i) o = j(r, Wi(a)) > -1, a.selected !== o && (a.selected = o); else if (N(Wi(a), r)) return void (e.selectedIndex !== s && (e.selectedIndex = s)); i || (e.selectedIndex = -1) } } function qi(e, t) { return t.every(function (t) { return !N(t, e) }) } function Wi(e) { return "_value" in e ? e._value : e.value } function Zi(e) { e.target.composing = !0 } function Gi(e) { e.target.composing && (e.target.composing = !1, Xi(e.target, "input")) } function Xi(e, t) { var n = document.createEvent("HTMLEvents"); n.initEvent(t, !0, !0), e.dispatchEvent(n) } function Yi(e) { return !e.componentInstance || e.data && e.data.transition ? e : Yi(e.componentInstance._vnode) } var Qi = { model: Vi, show: { bind: function (e, t, n) { var r = t.value, i = (n = Yi(n)).data && n.data.transition, o = e.__vOriginalDisplay = "none" === e.style.display ? "" : e.style.display; r && i ? (n.data.show = !0, Pi(n, function () { e.style.display = o })) : e.style.display = r ? o : "none" }, update: function (e, t, n) { var r = t.value; !r != !t.oldValue && ((n = Yi(n)).data && n.data.transition ? (n.data.show = !0, r ? Pi(n, function () { e.style.display = e.__vOriginalDisplay }) : Ri(n, function () { e.style.display = "none" })) : e.style.display = r ? e.__vOriginalDisplay : "none") }, unbind: function (e, t, n, r, i) { i || (e.style.display = e.__vOriginalDisplay) } } }, eo = { name: String, appear: Boolean, css: Boolean, mode: String, type: String, enterClass: String, leaveClass: String, enterToClass: String, leaveToClass: String, enterActiveClass: String, leaveActiveClass: String, appearClass: String, appearActiveClass: String, appearToClass: String, duration: [Number, String, Object] }; function to(e) { var t = e && e.componentOptions; return t && t.Ctor.options.abstract ? to(zt(t.children)) : e } function no(e) { var t = {}, n = e.$options; for (var r in n.propsData) t[r] = e[r]; var i = n._parentListeners; for (var o in i) t[b(o)] = i[o]; return t } function ro(e, t) { if (/\d-keep-alive$/.test(t.tag)) return e("keep-alive", { props: t.componentOptions.propsData }) } var io = function (e) { return e.tag || Ut(e) }, oo = function (e) { return "show" === e.name }, ao = { name: "transition", props: eo, abstract: !0, render: function (e) { var t = this, n = this.$slots.default; if (n && (n = n.filter(io)).length) { var r = this.mode, o = n[0]; if (function (e) { for (; e = e.parent;)if (e.data.transition) return !0 }(this.$vnode)) return o; var a = to(o); if (!a) return o; if (this._leaving) return ro(e, o); var s = "__transition-" + this._uid + "-"; a.key = null == a.key ? a.isComment ? s + "comment" : s + a.tag : i(a.key) ? 0 === String(a.key).indexOf(s) ? a.key : s + a.key : a.key; var c = (a.data || (a.data = {})).transition = no(this), u = this._vnode, l = to(u); if (a.data.directives && a.data.directives.some(oo) && (a.data.show = !0), l && l.data && !function (e, t) { return t.key === e.key && t.tag === e.tag }(a, l) && !Ut(l) && (!l.componentInstance || !l.componentInstance._vnode.isComment)) { var f = l.data.transition = A({}, c); if ("out-in" === r) return this._leaving = !0, it(f, "afterLeave", function () { t._leaving = !1, t.$forceUpdate() }), ro(e, o); if ("in-out" === r) { if (Ut(a)) return u; var p, d = function () { p() }; it(c, "afterEnter", d), it(c, "enterCancelled", d), it(f, "delayLeave", function (e) { p = e }) } } return o } } }, so = A({ tag: String, moveClass: String }, eo); function co(e) { e.elm._moveCb && e.elm._moveCb(), e.elm._enterCb && e.elm._enterCb() } function uo(e) { e.data.newPos = e.elm.getBoundingClientRect() } function lo(e) { var t = e.data.pos, n = e.data.newPos, r = t.left - n.left, i = t.top - n.top; if (r || i) { e.data.moved = !0; var o = e.elm.style; o.transform = o.WebkitTransform = "translate(" + r + "px," + i + "px)", o.transitionDuration = "0s" } } delete so.mode; var fo = { Transition: ao, TransitionGroup: { props: so, beforeMount: function () { var e = this, t = this._update; this._update = function (n, r) { var i = Zt(e); e.__patch__(e._vnode, e.kept, !1, !0), e._vnode = e.kept, i(), t.call(e, n, r) } }, render: function (e) { for (var t = this.tag || this.$vnode.data.tag || "span", n = Object.create(null), r = this.prevChildren = this.children, i = this.$slots.default || [], o = this.children = [], a = no(this), s = 0; s < i.length; s++) { var c = i[s]; c.tag && null != c.key && 0 !== String(c.key).indexOf("__vlist") && (o.push(c), n[c.key] = c, (c.data || (c.data = {})).transition = a) } if (r) { for (var u = [], l = [], f = 0; f < r.length; f++) { var p = r[f]; p.data.transition = a, p.data.pos = p.elm.getBoundingClientRect(), n[p.key] ? u.push(p) : l.push(p) } this.kept = e(t, null, u), this.removed = l } return e(t, null, o) }, updated: function () { var e = this.prevChildren, t = this.moveClass || (this.name || "v") + "-move"; e.length && this.hasMove(e[0].elm, t) && (e.forEach(co), e.forEach(uo), e.forEach(lo), this._reflow = document.body.offsetHeight, e.forEach(function (e) { if (e.data.moved) { var n = e.elm, r = n.style; Ni(n, t), r.transform = r.WebkitTransform = r.transitionDuration = "", n.addEventListener(Ai, n._moveCb = function e(r) { r && r.target !== n || r && !/transform$/.test(r.propertyName) || (n.removeEventListener(Ai, e), n._moveCb = null, ji(n, t)) }) } })) }, methods: { hasMove: function (e, t) { if (!wi) return !1; if (this._hasMove) return this._hasMove; var n = e.cloneNode(); e._transitionClasses && e._transitionClasses.forEach(function (e) { _i(n, e) }), gi(n, t), n.style.display = "none", this.$el.appendChild(n); var r = Mi(n); return this.$el.removeChild(n), this._hasMove = r.hasTransform } } } }; wn.config.mustUseProp = jn, wn.config.isReservedTag = Wn, wn.config.isReservedAttr = En, wn.config.getTagNamespace = Zn, wn.config.isUnknownElement = function (e) { if (!z) return !0; if (Wn(e)) return !1; if (e = e.toLowerCase(), null != Gn[e]) return Gn[e]; var t = document.createElement(e); return e.indexOf("-") > -1 ? Gn[e] = t.constructor === window.HTMLUnknownElement || t.constructor === window.HTMLElement : Gn[e] = /HTMLUnknownElement/.test(t.toString()) }, A(wn.options.directives, Qi), A(wn.options.components, fo), wn.prototype.__patch__ = z ? zi : S, wn.prototype.$mount = function (e, t) { return function (e, t, n) { var r; return e.$el = t, e.$options.render || (e.$options.render = ve), Yt(e, "beforeMount"), r = function () { e._update(e._render(), n) }, new fn(e, r, S, { before: function () { e._isMounted && !e._isDestroyed && Yt(e, "beforeUpdate") } }, !0), n = !1, null == e.$vnode && (e._isMounted = !0, Yt(e, "mounted")), e }(this, e = e && z ? Yn(e) : void 0, t) }, z && setTimeout(function () { F.devtools && ne && ne.emit("init", wn) }, 0); var po = /\{\{((?:.|\r?\n)+?)\}\}/g, vo = /[-.*+?^${}()|[\]\/\\]/g, ho = g(function (e) { var t = e[0].replace(vo, "\\$&"), n = e[1].replace(vo, "\\$&"); return new RegExp(t + "((?:.|\\n)+?)" + n, "g") }); var mo = { staticKeys: ["staticClass"], transformNode: function (e, t) { t.warn; var n = Fr(e, "class"); n && (e.staticClass = JSON.stringify(n)); var r = Ir(e, "class", !1); r && (e.classBinding = r) }, genData: function (e) { var t = ""; return e.staticClass && (t += "staticClass:" + e.staticClass + ","), e.classBinding && (t += "class:" + e.classBinding + ","), t } }; var yo, go = { staticKeys: ["staticStyle"], transformNode: function (e, t) { t.warn; var n = Fr(e, "style"); n && (e.staticStyle = JSON.stringify(ai(n))); var r = Ir(e, "style", !1); r && (e.styleBinding = r) }, genData: function (e) { var t = ""; return e.staticStyle && (t += "staticStyle:" + e.staticStyle + ","), e.styleBinding && (t += "style:(" + e.styleBinding + "),"), t } }, _o = function (e) { return (yo = yo || document.createElement("div")).innerHTML = e, yo.textContent }, bo = p("area,base,br,col,embed,frame,hr,img,input,isindex,keygen,link,meta,param,source,track,wbr"), $o = p("colgroup,dd,dt,li,options,p,td,tfoot,th,thead,tr,source"), wo = p("address,article,aside,base,blockquote,body,caption,col,colgroup,dd,details,dialog,div,dl,dt,fieldset,figcaption,figure,footer,form,h1,h2,h3,h4,h5,h6,head,header,hgroup,hr,html,legend,li,menuitem,meta,optgroup,option,param,rp,rt,source,style,summary,tbody,td,tfoot,th,thead,title,tr,track"), Co = /^\s*([^\s"'<>\/=]+)(?:\s*(=)\s*(?:"([^"]*)"+|'([^']*)'+|([^\s"'=<>`]+)))?/, xo = /^\s*((?:v-[\w-]+:|@|:|#)\[[^=]+\][^\s"'<>\/=]*)(?:\s*(=)\s*(?:"([^"]*)"+|'([^']*)'+|([^\s"'=<>`]+)))?/, ko = "[a-zA-Z_][\\-\\.0-9_a-zA-Z" + P.source + "]*", Ao = "((?:" + ko + "\\:)?" + ko + ")", Oo = new RegExp("^<" + Ao), So = /^\s*(\/?)>/, To = new RegExp("^<\\/" + Ao + "[^>]*>"), Eo = /^<!DOCTYPE [^>]+>/i, No = /^<!\--/, jo = /^<!\[/, Do = p("script,style,textarea", !0), Lo = {}, Mo = { "&lt;": "<", "&gt;": ">", "&quot;": '"', "&amp;": "&", "&#10;": "\n", "&#9;": "\t", "&#39;": "'" }, Io = /&(?:lt|gt|quot|amp|#39);/g, Fo = /&(?:lt|gt|quot|amp|#39|#10|#9);/g, Po = p("pre,textarea", !0), Ro = function (e, t) { return e && Po(e) && "\n" === t[0] }; function Ho(e, t) { var n = t ? Fo : Io; return e.replace(n, function (e) { return Mo[e] }) } var Bo, Uo, zo, Vo, Ko, Jo, qo, Wo, Zo = /^@|^v-on:/, Go = /^v-|^@|^:/, Xo = /([\s\S]*?)\s+(?:in|of)\s+([\s\S]*)/, Yo = /,([^,\}\]]*)(?:,([^,\}\]]*))?$/, Qo = /^\(|\)$/g, ea = /^\[.*\]$/, ta = /:(.*)$/, na = /^:|^\.|^v-bind:/, ra = /\.[^.\]]+(?=[^\]]*$)/g, ia = /^v-slot(:|$)|^#/, oa = /[\r\n]/, aa = /\s+/g, sa = g(_o), ca = "_empty_"; function ua(e, t, n) { return { type: 1, tag: e, attrsList: t, attrsMap: ma(t), rawAttrsMap: {}, parent: n, children: [] } } function la(e, t) { Bo = t.warn || Sr, Jo = t.isPreTag || T, qo = t.mustUseProp || T, Wo = t.getTagNamespace || T; t.isReservedTag; zo = Tr(t.modules, "transformNode"), Vo = Tr(t.modules, "preTransformNode"), Ko = Tr(t.modules, "postTransformNode"), Uo = t.delimiters; var n, r, i = [], o = !1 !== t.preserveWhitespace, a = t.whitespace, s = !1, c = !1; function u(e) { if (l(e), s || e.processed || (e = fa(e, t)), i.length || e === n || n.if && (e.elseif || e.else) && da(n, { exp: e.elseif, block: e }), r && !e.forbidden) if (e.elseif || e.else) a = e, (u = function (e) { var t = e.length; for (; t--;) { if (1 === e[t].type) return e[t]; e.pop() } }(r.children)) && u.if && da(u, { exp: a.elseif, block: a }); else { if (e.slotScope) { var o = e.slotTarget || '"default"'; (r.scopedSlots || (r.scopedSlots = {}))[o] = e } r.children.push(e), e.parent = r } var a, u; e.children = e.children.filter(function (e) { return !e.slotScope }), l(e), e.pre && (s = !1), Jo(e.tag) && (c = !1); for (var f = 0; f < Ko.length; f++)Ko[f](e, t) } function l(e) { if (!c) for (var t; (t = e.children[e.children.length - 1]) && 3 === t.type && " " === t.text;)e.children.pop() } return function (e, t) { for (var n, r, i = [], o = t.expectHTML, a = t.isUnaryTag || T, s = t.canBeLeftOpenTag || T, c = 0; e;) { if (n = e, r && Do(r)) { var u = 0, l = r.toLowerCase(), f = Lo[l] || (Lo[l] = new RegExp("([\\s\\S]*?)(</" + l + "[^>]*>)", "i")), p = e.replace(f, function (e, n, r) { return u = r.length, Do(l) || "noscript" === l || (n = n.replace(/<!\--([\s\S]*?)-->/g, "$1").replace(/<!\[CDATA\[([\s\S]*?)]]>/g, "$1")), Ro(l, n) && (n = n.slice(1)), t.chars && t.chars(n), "" }); c += e.length - p.length, e = p, A(l, c - u, c) } else { var d = e.indexOf("<"); if (0 === d) { if (No.test(e)) { var v = e.indexOf("--\x3e"); if (v >= 0) { t.shouldKeepComment && t.comment(e.substring(4, v), c, c + v + 3), C(v + 3); continue } } if (jo.test(e)) { var h = e.indexOf("]>"); if (h >= 0) { C(h + 2); continue } } var m = e.match(Eo); if (m) { C(m[0].length); continue } var y = e.match(To); if (y) { var g = c; C(y[0].length), A(y[1], g, c); continue } var _ = x(); if (_) { k(_), Ro(_.tagName, e) && C(1); continue } } var b = void 0, $ = void 0, w = void 0; if (d >= 0) { for ($ = e.slice(d); !(To.test($) || Oo.test($) || No.test($) || jo.test($) || (w = $.indexOf("<", 1)) < 0);)d += w, $ = e.slice(d); b = e.substring(0, d) } d < 0 && (b = e), b && C(b.length), t.chars && b && t.chars(b, c - b.length, c) } if (e === n) { t.chars && t.chars(e); break } } function C(t) { c += t, e = e.substring(t) } function x() { var t = e.match(Oo); if (t) { var n, r, i = { tagName: t[1], attrs: [], start: c }; for (C(t[0].length); !(n = e.match(So)) && (r = e.match(xo) || e.match(Co));)r.start = c, C(r[0].length), r.end = c, i.attrs.push(r); if (n) return i.unarySlash = n[1], C(n[0].length), i.end = c, i } } function k(e) { var n = e.tagName, c = e.unarySlash; o && ("p" === r && wo(n) && A(r), s(n) && r === n && A(n)); for (var u = a(n) || !!c, l = e.attrs.length, f = new Array(l), p = 0; p < l; p++) { var d = e.attrs[p], v = d[3] || d[4] || d[5] || "", h = "a" === n && "href" === d[1] ? t.shouldDecodeNewlinesForHref : t.shouldDecodeNewlines; f[p] = { name: d[1], value: Ho(v, h) } } u || (i.push({ tag: n, lowerCasedTag: n.toLowerCase(), attrs: f, start: e.start, end: e.end }), r = n), t.start && t.start(n, f, u, e.start, e.end) } function A(e, n, o) { var a, s; if (null == n && (n = c), null == o && (o = c), e) for (s = e.toLowerCase(), a = i.length - 1; a >= 0 && i[a].lowerCasedTag !== s; a--); else a = 0; if (a >= 0) { for (var u = i.length - 1; u >= a; u--)t.end && t.end(i[u].tag, n, o); i.length = a, r = a && i[a - 1].tag } else "br" === s ? t.start && t.start(e, [], !0, n, o) : "p" === s && (t.start && t.start(e, [], !1, n, o), t.end && t.end(e, n, o)) } A() }(e, { warn: Bo, expectHTML: t.expectHTML, isUnaryTag: t.isUnaryTag, canBeLeftOpenTag: t.canBeLeftOpenTag, shouldDecodeNewlines: t.shouldDecodeNewlines, shouldDecodeNewlinesForHref: t.shouldDecodeNewlinesForHref, shouldKeepComment: t.comments, outputSourceRange: t.outputSourceRange, start: function (e, o, a, l, f) { var p = r && r.ns || Wo(e); q && "svg" === p && (o = function (e) { for (var t = [], n = 0; n < e.length; n++) { var r = e[n]; ya.test(r.name) || (r.name = r.name.replace(ga, ""), t.push(r)) } return t }(o)); var d, v = ua(e, o, r); p && (v.ns = p), "style" !== (d = v).tag && ("script" !== d.tag || d.attrsMap.type && "text/javascript" !== d.attrsMap.type) || te() || (v.forbidden = !0); for (var h = 0; h < Vo.length; h++)v = Vo[h](v, t) || v; s || (!function (e) { null != Fr(e, "v-pre") && (e.pre = !0) }(v), v.pre && (s = !0)), Jo(v.tag) && (c = !0), s ? function (e) { var t = e.attrsList, n = t.length; if (n) for (var r = e.attrs = new Array(n), i = 0; i < n; i++)r[i] = { name: t[i].name, value: JSON.stringify(t[i].value) }, null != t[i].start && (r[i].start = t[i].start, r[i].end = t[i].end); else e.pre || (e.plain = !0) }(v) : v.processed || (pa(v), function (e) { var t = Fr(e, "v-if"); if (t) e.if = t, da(e, { exp: t, block: e }); else { null != Fr(e, "v-else") && (e.else = !0); var n = Fr(e, "v-else-if"); n && (e.elseif = n) } }(v), function (e) { null != Fr(e, "v-once") && (e.once = !0) }(v)), n || (n = v), a ? u(v) : (r = v, i.push(v)) }, end: function (e, t, n) { var o = i[i.length - 1]; i.length -= 1, r = i[i.length - 1], u(o) }, chars: function (e, t, n) { if (r && (!q || "textarea" !== r.tag || r.attrsMap.placeholder !== e)) { var i, u, l, f = r.children; if (e = c || e.trim() ? "script" === (i = r).tag || "style" === i.tag ? e : sa(e) : f.length ? a ? "condense" === a && oa.test(e) ? "" : " " : o ? " " : "" : "") c || "condense" !== a || (e = e.replace(aa, " ")), !s && " " !== e && (u = function (e, t) { var n = t ? ho(t) : po; if (n.test(e)) { for (var r, i, o, a = [], s = [], c = n.lastIndex = 0; r = n.exec(e);) { (i = r.index) > c && (s.push(o = e.slice(c, i)), a.push(JSON.stringify(o))); var u = Ar(r[1].trim()); a.push("_s(" + u + ")"), s.push({ "@binding": u }), c = i + r[0].length } return c < e.length && (s.push(o = e.slice(c)), a.push(JSON.stringify(o))), { expression: a.join("+"), tokens: s } } }(e, Uo)) ? l = { type: 2, expression: u.expression, tokens: u.tokens, text: e } : " " === e && f.length && " " === f[f.length - 1].text || (l = { type: 3, text: e }), l && f.push(l) } }, comment: function (e, t, n) { if (r) { var i = { type: 3, text: e, isComment: !0 }; r.children.push(i) } } }), n } function fa(e, t) { var n, r; (r = Ir(n = e, "key")) && (n.key = r), e.plain = !e.key && !e.scopedSlots && !e.attrsList.length, function (e) { var t = Ir(e, "ref"); t && (e.ref = t, e.refInFor = function (e) { var t = e; for (; t;) { if (void 0 !== t.for) return !0; t = t.parent } return !1 }(e)) }(e), function (e) { var t; "template" === e.tag ? (t = Fr(e, "scope"), e.slotScope = t || Fr(e, "slot-scope")) : (t = Fr(e, "slot-scope")) && (e.slotScope = t); var n = Ir(e, "slot"); n && (e.slotTarget = '""' === n ? '"default"' : n, e.slotTargetDynamic = !(!e.attrsMap[":slot"] && !e.attrsMap["v-bind:slot"]), "template" === e.tag || e.slotScope || Nr(e, "slot", n, function (e, t) { return e.rawAttrsMap[":" + t] || e.rawAttrsMap["v-bind:" + t] || e.rawAttrsMap[t] }(e, "slot"))); if ("template" === e.tag) { var r = Pr(e, ia); if (r) { var i = va(r), o = i.name, a = i.dynamic; e.slotTarget = o, e.slotTargetDynamic = a, e.slotScope = r.value || ca } } else { var s = Pr(e, ia); if (s) { var c = e.scopedSlots || (e.scopedSlots = {}), u = va(s), l = u.name, f = u.dynamic, p = c[l] = ua("template", [], e); p.slotTarget = l, p.slotTargetDynamic = f, p.children = e.children.filter(function (e) { if (!e.slotScope) return e.parent = p, !0 }), p.slotScope = s.value || ca, e.children = [], e.plain = !1 } } }(e), function (e) { "slot" === e.tag && (e.slotName = Ir(e, "name")) }(e), function (e) { var t; (t = Ir(e, "is")) && (e.component = t); null != Fr(e, "inline-template") && (e.inlineTemplate = !0) }(e); for (var i = 0; i < zo.length; i++)e = zo[i](e, t) || e; return function (e) { var t, n, r, i, o, a, s, c, u = e.attrsList; for (t = 0, n = u.length; t < n; t++)if (r = i = u[t].name, o = u[t].value, Go.test(r)) if (e.hasBindings = !0, (a = ha(r.replace(Go, ""))) && (r = r.replace(ra, "")), na.test(r)) r = r.replace(na, ""), o = Ar(o), (c = ea.test(r)) && (r = r.slice(1, -1)), a && (a.prop && !c && "innerHtml" === (r = b(r)) && (r = "innerHTML"), a.camel && !c && (r = b(r)), a.sync && (s = Br(o, "$event"), c ? Mr(e, '"update:"+(' + r + ")", s, null, !1, 0, u[t], !0) : (Mr(e, "update:" + b(r), s, null, !1, 0, u[t]), C(r) !== b(r) && Mr(e, "update:" + C(r), s, null, !1, 0, u[t])))), a && a.prop || !e.component && qo(e.tag, e.attrsMap.type, r) ? Er(e, r, o, u[t], c) : Nr(e, r, o, u[t], c); else if (Zo.test(r)) r = r.replace(Zo, ""), (c = ea.test(r)) && (r = r.slice(1, -1)), Mr(e, r, o, a, !1, 0, u[t], c); else { var l = (r = r.replace(Go, "")).match(ta), f = l && l[1]; c = !1, f && (r = r.slice(0, -(f.length + 1)), ea.test(f) && (f = f.slice(1, -1), c = !0)), Dr(e, r, i, o, f, c, a, u[t]) } else Nr(e, r, JSON.stringify(o), u[t]), !e.component && "muted" === r && qo(e.tag, e.attrsMap.type, r) && Er(e, r, "true", u[t]) }(e), e } function pa(e) { var t; if (t = Fr(e, "v-for")) { var n = function (e) { var t = e.match(Xo); if (!t) return; var n = {}; n.for = t[2].trim(); var r = t[1].trim().replace(Qo, ""), i = r.match(Yo); i ? (n.alias = r.replace(Yo, "").trim(), n.iterator1 = i[1].trim(), i[2] && (n.iterator2 = i[2].trim())) : n.alias = r; return n }(t); n && A(e, n) } } function da(e, t) { e.ifConditions || (e.ifConditions = []), e.ifConditions.push(t) } function va(e) { var t = e.name.replace(ia, ""); return t || "#" !== e.name[0] && (t = "default"), ea.test(t) ? { name: t.slice(1, -1), dynamic: !0 } : { name: '"' + t + '"', dynamic: !1 } } function ha(e) { var t = e.match(ra); if (t) { var n = {}; return t.forEach(function (e) { n[e.slice(1)] = !0 }), n } } function ma(e) { for (var t = {}, n = 0, r = e.length; n < r; n++)t[e[n].name] = e[n].value; return t } var ya = /^xmlns:NS\d+/, ga = /^NS\d+:/; function _a(e) { return ua(e.tag, e.attrsList.slice(), e.parent) } var ba = [mo, go, { preTransformNode: function (e, t) { if ("input" === e.tag) { var n, r = e.attrsMap; if (!r["v-model"]) return; if ((r[":type"] || r["v-bind:type"]) && (n = Ir(e, "type")), r.type || n || !r["v-bind"] || (n = "(" + r["v-bind"] + ").type"), n) { var i = Fr(e, "v-if", !0), o = i ? "&&(" + i + ")" : "", a = null != Fr(e, "v-else", !0), s = Fr(e, "v-else-if", !0), c = _a(e); pa(c), jr(c, "type", "checkbox"), fa(c, t), c.processed = !0, c.if = "(" + n + ")==='checkbox'" + o, da(c, { exp: c.if, block: c }); var u = _a(e); Fr(u, "v-for", !0), jr(u, "type", "radio"), fa(u, t), da(c, { exp: "(" + n + ")==='radio'" + o, block: u }); var l = _a(e); return Fr(l, "v-for", !0), jr(l, ":type", n), fa(l, t), da(c, { exp: i, block: l }), a ? c.else = !0 : s && (c.elseif = s), c } } } }]; var $a, wa, Ca = { expectHTML: !0, modules: ba, directives: { model: function (e, t, n) { var r = t.value, i = t.modifiers, o = e.tag, a = e.attrsMap.type; if (e.component) return Hr(e, r, i), !1; if ("select" === o) !function (e, t, n) { var r = 'var $$selectedVal = Array.prototype.filter.call($event.target.options,function(o){return o.selected}).map(function(o){var val = "_value" in o ? o._value : o.value;return ' + (n && n.number ? "_n(val)" : "val") + "});"; r = r + " " + Br(t, "$event.target.multiple ? $$selectedVal : $$selectedVal[0]"), Mr(e, "change", r, null, !0) }(e, r, i); else if ("input" === o && "checkbox" === a) !function (e, t, n) { var r = n && n.number, i = Ir(e, "value") || "null", o = Ir(e, "true-value") || "true", a = Ir(e, "false-value") || "false"; Er(e, "checked", "Array.isArray(" + t + ")?_i(" + t + "," + i + ")>-1" + ("true" === o ? ":(" + t + ")" : ":_q(" + t + "," + o + ")")), Mr(e, "change", "var $$a=" + t + ",$$el=$event.target,$$c=$$el.checked?(" + o + "):(" + a + ");if(Array.isArray($$a)){var $$v=" + (r ? "_n(" + i + ")" : i) + ",$$i=_i($$a,$$v);if($$el.checked){$$i<0&&(" + Br(t, "$$a.concat([$$v])") + ")}else{$$i>-1&&(" + Br(t, "$$a.slice(0,$$i).concat($$a.slice($$i+1))") + ")}}else{" + Br(t, "$$c") + "}", null, !0) }(e, r, i); else if ("input" === o && "radio" === a) !function (e, t, n) { var r = n && n.number, i = Ir(e, "value") || "null"; Er(e, "checked", "_q(" + t + "," + (i = r ? "_n(" + i + ")" : i) + ")"), Mr(e, "change", Br(t, i), null, !0) }(e, r, i); else if ("input" === o || "textarea" === o) !function (e, t, n) { var r = e.attrsMap.type, i = n || {}, o = i.lazy, a = i.number, s = i.trim, c = !o && "range" !== r, u = o ? "change" : "range" === r ? Wr : "input", l = "$event.target.value"; s && (l = "$event.target.value.trim()"), a && (l = "_n(" + l + ")"); var f = Br(t, l); c && (f = "if($event.target.composing)return;" + f), Er(e, "value", "(" + t + ")"), Mr(e, u, f, null, !0), (s || a) && Mr(e, "blur", "$forceUpdate()") }(e, r, i); else if (!F.isReservedTag(o)) return Hr(e, r, i), !1; return !0 }, text: function (e, t) { t.value && Er(e, "textContent", "_s(" + t.value + ")", t) }, html: function (e, t) { t.value && Er(e, "innerHTML", "_s(" + t.value + ")", t) } }, isPreTag: function (e) { return "pre" === e }, isUnaryTag: bo, mustUseProp: jn, canBeLeftOpenTag: $o, isReservedTag: Wn, getTagNamespace: Zn, staticKeys: function (e) { return e.reduce(function (e, t) { return e.concat(t.staticKeys || []) }, []).join(",") }(ba) }, xa = g(function (e) { return p("type,tag,attrsList,attrsMap,plain,parent,children,attrs,start,end,rawAttrsMap" + (e ? "," + e : "")) }); function ka(e, t) { e && ($a = xa(t.staticKeys || ""), wa = t.isReservedTag || T, function e(t) { t.static = function (e) { if (2 === e.type) return !1; if (3 === e.type) return !0; return !(!e.pre && (e.hasBindings || e.if || e.for || d(e.tag) || !wa(e.tag) || function (e) { for (; e.parent;) { if ("template" !== (e = e.parent).tag) return !1; if (e.for) return !0 } return !1 }(e) || !Object.keys(e).every($a))) }(t); if (1 === t.type) { if (!wa(t.tag) && "slot" !== t.tag && null == t.attrsMap["inline-template"]) return; for (var n = 0, r = t.children.length; n < r; n++) { var i = t.children[n]; e(i), i.static || (t.static = !1) } if (t.ifConditions) for (var o = 1, a = t.ifConditions.length; o < a; o++) { var s = t.ifConditions[o].block; e(s), s.static || (t.static = !1) } } }(e), function e(t, n) { if (1 === t.type) { if ((t.static || t.once) && (t.staticInFor = n), t.static && t.children.length && (1 !== t.children.length || 3 !== t.children[0].type)) return void (t.staticRoot = !0); if (t.staticRoot = !1, t.children) for (var r = 0, i = t.children.length; r < i; r++)e(t.children[r], n || !!t.for); if (t.ifConditions) for (var o = 1, a = t.ifConditions.length; o < a; o++)e(t.ifConditions[o].block, n) } }(e, !1)) } var Aa = /^([\w$_]+|\([^)]*?\))\s*=>|^function\s*(?:[\w$]+)?\s*\(/, Oa = /\([^)]*?\);*$/, Sa = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\['[^']*?']|\["[^"]*?"]|\[\d+]|\[[A-Za-z_$][\w$]*])*$/, Ta = { esc: 27, tab: 9, enter: 13, space: 32, up: 38, left: 37, right: 39, down: 40, delete: [8, 46] }, Ea = { esc: ["Esc", "Escape"], tab: "Tab", enter: "Enter", space: [" ", "Spacebar"], up: ["Up", "ArrowUp"], left: ["Left", "ArrowLeft"], right: ["Right", "ArrowRight"], down: ["Down", "ArrowDown"], delete: ["Backspace", "Delete", "Del"] }, Na = function (e) { return "if(" + e + ")return null;" }, ja = { stop: "$event.stopPropagation();", prevent: "$event.preventDefault();", self: Na("$event.target !== $event.currentTarget"), ctrl: Na("!$event.ctrlKey"), shift: Na("!$event.shiftKey"), alt: Na("!$event.altKey"), meta: Na("!$event.metaKey"), left: Na("'button' in $event && $event.button !== 0"), middle: Na("'button' in $event && $event.button !== 1"), right: Na("'button' in $event && $event.button !== 2") }; function Da(e, t) { var n = t ? "nativeOn:" : "on:", r = "", i = ""; for (var o in e) { var a = La(e[o]); e[o] && e[o].dynamic ? i += o + "," + a + "," : r += '"' + o + '":' + a + "," } return r = "{" + r.slice(0, -1) + "}", i ? n + "_d(" + r + ",[" + i.slice(0, -1) + "])" : n + r } function La(e) { if (!e) return "function(){}"; if (Array.isArray(e)) return "[" + e.map(function (e) { return La(e) }).join(",") + "]"; var t = Sa.test(e.value), n = Aa.test(e.value), r = Sa.test(e.value.replace(Oa, "")); if (e.modifiers) { var i = "", o = "", a = []; for (var s in e.modifiers) if (ja[s]) o += ja[s], Ta[s] && a.push(s); else if ("exact" === s) { var c = e.modifiers; o += Na(["ctrl", "shift", "alt", "meta"].filter(function (e) { return !c[e] }).map(function (e) { return "$event." + e + "Key" }).join("||")) } else a.push(s); return a.length && (i += function (e) { return "if(!$event.type.indexOf('key')&&" + e.map(Ma).join("&&") + ")return null;" }(a)), o && (i += o), "function($event){" + i + (t ? "return " + e.value + "($event)" : n ? "return (" + e.value + ")($event)" : r ? "return " + e.value : e.value) + "}" } return t || n ? e.value : "function($event){" + (r ? "return " + e.value : e.value) + "}" } function Ma(e) { var t = parseInt(e, 10); if (t) return "$event.keyCode!==" + t; var n = Ta[e], r = Ea[e]; return "_k($event.keyCode," + JSON.stringify(e) + "," + JSON.stringify(n) + ",$event.key," + JSON.stringify(r) + ")" } var Ia = { on: function (e, t) { e.wrapListeners = function (e) { return "_g(" + e + "," + t.value + ")" } }, bind: function (e, t) { e.wrapData = function (n) { return "_b(" + n + ",'" + e.tag + "'," + t.value + "," + (t.modifiers && t.modifiers.prop ? "true" : "false") + (t.modifiers && t.modifiers.sync ? ",true" : "") + ")" } }, cloak: S }, Fa = function (e) { this.options = e, this.warn = e.warn || Sr, this.transforms = Tr(e.modules, "transformCode"), this.dataGenFns = Tr(e.modules, "genData"), this.directives = A(A({}, Ia), e.directives); var t = e.isReservedTag || T; this.maybeComponent = function (e) { return !!e.component || !t(e.tag) }, this.onceId = 0, this.staticRenderFns = [], this.pre = !1 }; function Pa(e, t) { var n = new Fa(t); return { render: "with(this){return " + (e ? Ra(e, n) : '_c("div")') + "}", staticRenderFns: n.staticRenderFns } } function Ra(e, t) { if (e.parent && (e.pre = e.pre || e.parent.pre), e.staticRoot && !e.staticProcessed) return Ha(e, t); if (e.once && !e.onceProcessed) return Ba(e, t); if (e.for && !e.forProcessed) return za(e, t); if (e.if && !e.ifProcessed) return Ua(e, t); if ("template" !== e.tag || e.slotTarget || t.pre) { if ("slot" === e.tag) return function (e, t) { var n = e.slotName || '"default"', r = qa(e, t), i = "_t(" + n + (r ? "," + r : ""), o = e.attrs || e.dynamicAttrs ? Ga((e.attrs || []).concat(e.dynamicAttrs || []).map(function (e) { return { name: b(e.name), value: e.value, dynamic: e.dynamic } })) : null, a = e.attrsMap["v-bind"]; !o && !a || r || (i += ",null"); o && (i += "," + o); a && (i += (o ? "" : ",null") + "," + a); return i + ")" }(e, t); var n; if (e.component) n = function (e, t, n) { var r = t.inlineTemplate ? null : qa(t, n, !0); return "_c(" + e + "," + Va(t, n) + (r ? "," + r : "") + ")" }(e.component, e, t); else { var r; (!e.plain || e.pre && t.maybeComponent(e)) && (r = Va(e, t)); var i = e.inlineTemplate ? null : qa(e, t, !0); n = "_c('" + e.tag + "'" + (r ? "," + r : "") + (i ? "," + i : "") + ")" } for (var o = 0; o < t.transforms.length; o++)n = t.transforms[o](e, n); return n } return qa(e, t) || "void 0" } function Ha(e, t) { e.staticProcessed = !0; var n = t.pre; return e.pre && (t.pre = e.pre), t.staticRenderFns.push("with(this){return " + Ra(e, t) + "}"), t.pre = n, "_m(" + (t.staticRenderFns.length - 1) + (e.staticInFor ? ",true" : "") + ")" } function Ba(e, t) { if (e.onceProcessed = !0, e.if && !e.ifProcessed) return Ua(e, t); if (e.staticInFor) { for (var n = "", r = e.parent; r;) { if (r.for) { n = r.key; break } r = r.parent } return n ? "_o(" + Ra(e, t) + "," + t.onceId++ + "," + n + ")" : Ra(e, t) } return Ha(e, t) } function Ua(e, t, n, r) { return e.ifProcessed = !0, function e(t, n, r, i) { if (!t.length) return i || "_e()"; var o = t.shift(); return o.exp ? "(" + o.exp + ")?" + a(o.block) + ":" + e(t, n, r, i) : "" + a(o.block); function a(e) { return r ? r(e, n) : e.once ? Ba(e, n) : Ra(e, n) } }(e.ifConditions.slice(), t, n, r) } function za(e, t, n, r) { var i = e.for, o = e.alias, a = e.iterator1 ? "," + e.iterator1 : "", s = e.iterator2 ? "," + e.iterator2 : ""; return e.forProcessed = !0, (r || "_l") + "((" + i + "),function(" + o + a + s + "){return " + (n || Ra)(e, t) + "})" } function Va(e, t) { var n = "{", r = function (e, t) { var n = e.directives; if (!n) return; var r, i, o, a, s = "directives:[", c = !1; for (r = 0, i = n.length; r < i; r++) { o = n[r], a = !0; var u = t.directives[o.name]; u && (a = !!u(e, o, t.warn)), a && (c = !0, s += '{name:"' + o.name + '",rawName:"' + o.rawName + '"' + (o.value ? ",value:(" + o.value + "),expression:" + JSON.stringify(o.value) : "") + (o.arg ? ",arg:" + (o.isDynamicArg ? o.arg : '"' + o.arg + '"') : "") + (o.modifiers ? ",modifiers:" + JSON.stringify(o.modifiers) : "") + "},") } if (c) return s.slice(0, -1) + "]" }(e, t); r && (n += r + ","), e.key && (n += "key:" + e.key + ","), e.ref && (n += "ref:" + e.ref + ","), e.refInFor && (n += "refInFor:true,"), e.pre && (n += "pre:true,"), e.component && (n += 'tag:"' + e.tag + '",'); for (var i = 0; i < t.dataGenFns.length; i++)n += t.dataGenFns[i](e); if (e.attrs && (n += "attrs:" + Ga(e.attrs) + ","), e.props && (n += "domProps:" + Ga(e.props) + ","), e.events && (n += Da(e.events, !1) + ","), e.nativeEvents && (n += Da(e.nativeEvents, !0) + ","), e.slotTarget && !e.slotScope && (n += "slot:" + e.slotTarget + ","), e.scopedSlots && (n += function (e, t, n) { var r = e.for || Object.keys(t).some(function (e) { var n = t[e]; return n.slotTargetDynamic || n.if || n.for || Ka(n) }), i = !!e.if; if (!r) for (var o = e.parent; o;) { if (o.slotScope && o.slotScope !== ca || o.for) { r = !0; break } o.if && (i = !0), o = o.parent } var a = Object.keys(t).map(function (e) { return Ja(t[e], n) }).join(","); return "scopedSlots:_u([" + a + "]" + (r ? ",null,true" : "") + (!r && i ? ",null,false," + function (e) { var t = 5381, n = e.length; for (; n;)t = 33 * t ^ e.charCodeAt(--n); return t >>> 0 }(a) : "") + ")" }(e, e.scopedSlots, t) + ","), e.model && (n += "model:{value:" + e.model.value + ",callback:" + e.model.callback + ",expression:" + e.model.expression + "},"), e.inlineTemplate) { var o = function (e, t) { var n = e.children[0]; if (n && 1 === n.type) { var r = Pa(n, t.options); return "inlineTemplate:{render:function(){" + r.render + "},staticRenderFns:[" + r.staticRenderFns.map(function (e) { return "function(){" + e + "}" }).join(",") + "]}" } }(e, t); o && (n += o + ",") } return n = n.replace(/,$/, "") + "}", e.dynamicAttrs && (n = "_b(" + n + ',"' + e.tag + '",' + Ga(e.dynamicAttrs) + ")"), e.wrapData && (n = e.wrapData(n)), e.wrapListeners && (n = e.wrapListeners(n)), n } function Ka(e) { return 1 === e.type && ("slot" === e.tag || e.children.some(Ka)) } function Ja(e, t) { var n = e.attrsMap["slot-scope"]; if (e.if && !e.ifProcessed && !n) return Ua(e, t, Ja, "null"); if (e.for && !e.forProcessed) return za(e, t, Ja); var r = e.slotScope === ca ? "" : String(e.slotScope), i = "function(" + r + "){return " + ("template" === e.tag ? e.if && n ? "(" + e.if + ")?" + (qa(e, t) || "undefined") + ":undefined" : qa(e, t) || "undefined" : Ra(e, t)) + "}", o = r ? "" : ",proxy:true"; return "{key:" + (e.slotTarget || '"default"') + ",fn:" + i + o + "}" } function qa(e, t, n, r, i) { var o = e.children; if (o.length) { var a = o[0]; if (1 === o.length && a.for && "template" !== a.tag && "slot" !== a.tag) { var s = n ? t.maybeComponent(a) ? ",1" : ",0" : ""; return "" + (r || Ra)(a, t) + s } var c = n ? function (e, t) { for (var n = 0, r = 0; r < e.length; r++) { var i = e[r]; if (1 === i.type) { if (Wa(i) || i.ifConditions && i.ifConditions.some(function (e) { return Wa(e.block) })) { n = 2; break } (t(i) || i.ifConditions && i.ifConditions.some(function (e) { return t(e.block) })) && (n = 1) } } return n }(o, t.maybeComponent) : 0, u = i || Za; return "[" + o.map(function (e) { return u(e, t) }).join(",") + "]" + (c ? "," + c : "") } } function Wa(e) { return void 0 !== e.for || "template" === e.tag || "slot" === e.tag } function Za(e, t) { return 1 === e.type ? Ra(e, t) : 3 === e.type && e.isComment ? (r = e, "_e(" + JSON.stringify(r.text) + ")") : "_v(" + (2 === (n = e).type ? n.expression : Xa(JSON.stringify(n.text))) + ")"; var n, r } function Ga(e) { for (var t = "", n = "", r = 0; r < e.length; r++) { var i = e[r], o = Xa(i.value); i.dynamic ? n += i.name + "," + o + "," : t += '"' + i.name + '":' + o + "," } return t = "{" + t.slice(0, -1) + "}", n ? "_d(" + t + ",[" + n.slice(0, -1) + "])" : t } function Xa(e) { return e.replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029") } new RegExp("\\b" + "do,if,for,let,new,try,var,case,else,with,await,break,catch,class,const,super,throw,while,yield,delete,export,import,return,switch,default,extends,finally,continue,debugger,function,arguments".split(",").join("\\b|\\b") + "\\b"); function Ya(e, t) { try { return new Function(e) } catch (n) { return t.push({ err: n, code: e }), S } } function Qa(e) { var t = Object.create(null); return function (n, r, i) { (r = A({}, r)).warn; delete r.warn; var o = r.delimiters ? String(r.delimiters) + n : n; if (t[o]) return t[o]; var a = e(n, r), s = {}, c = []; return s.render = Ya(a.render, c), s.staticRenderFns = a.staticRenderFns.map(function (e) { return Ya(e, c) }), t[o] = s } } var es, ts, ns = (es = function (e, t) { var n = la(e.trim(), t); !1 !== t.optimize && ka(n, t); var r = Pa(n, t); return { ast: n, render: r.render, staticRenderFns: r.staticRenderFns } }, function (e) { function t(t, n) { var r = Object.create(e), i = [], o = []; if (n) for (var a in n.modules && (r.modules = (e.modules || []).concat(n.modules)), n.directives && (r.directives = A(Object.create(e.directives || null), n.directives)), n) "modules" !== a && "directives" !== a && (r[a] = n[a]); r.warn = function (e, t, n) { (n ? o : i).push(e) }; var s = es(t.trim(), r); return s.errors = i, s.tips = o, s } return { compile: t, compileToFunctions: Qa(t) } })(Ca), rs = (ns.compile, ns.compileToFunctions); function is(e) { return (ts = ts || document.createElement("div")).innerHTML = e ? '<a href="\n"/>' : '<div a="\n"/>', ts.innerHTML.indexOf("&#10;") > 0 } var os = !!z && is(!1), as = !!z && is(!0), ss = g(function (e) { var t = Yn(e); return t && t.innerHTML }), cs = wn.prototype.$mount; return wn.prototype.$mount = function (e, t) { if ((e = e && Yn(e)) === document.body || e === document.documentElement) return this; var n = this.$options; if (!n.render) { var r = n.template; if (r) if ("string" == typeof r) "#" === r.charAt(0) && (r = ss(r)); else { if (!r.nodeType) return this; r = r.innerHTML } else e && (r = function (e) { if (e.outerHTML) return e.outerHTML; var t = document.createElement("div"); return t.appendChild(e.cloneNode(!0)), t.innerHTML }(e)); if (r) { var i = rs(r, { outputSourceRange: !1, shouldDecodeNewlines: os, shouldDecodeNewlinesForHref: as, delimiters: n.delimiters, comments: n.comments }, this), o = i.render, a = i.staticRenderFns; n.render = o, n.staticRenderFns = a } } return cs.call(this, e, t) }, wn.compile = rs, wn });
                /* WEBPACK VAR INJECTION */
            }.call(this, __webpack_require__(/*! ./../../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js"), __webpack_require__(/*! ./../../timers-browserify/main.js */ "./node_modules/timers-browserify/main.js").setImmediate))

            /***/
        }),

/***/ "./node_modules/webpack/buildin/global.js":
/*!***********************************!*\
  !*** (webpack)/buildin/global.js ***!
  \***********************************/
/*! no static exports found */
/***/ (function (module, exports) {

            var g;

            // This works in non-strict mode
            g = (function () {
                return this;
            })();

            try {
                // This works if eval is allowed (see CSP)
                g = g || new Function("return this")();
            } catch (e) {
                // This works if the window reference is available
                if (typeof window === "object") g = window;
            }

            // g can still be undefined, but nothing to do about it...
            // We return undefined, instead of nothing here, so it's
            // easier to handle this case. if(!global) { ...}

            module.exports = g;


            /***/
        }),

/***/ "./node_modules/webpack/buildin/harmony-module.js":
/*!*******************************************!*\
  !*** (webpack)/buildin/harmony-module.js ***!
  \*******************************************/
/*! no static exports found */
/***/ (function (module, exports) {

            module.exports = function (originalModule) {
                if (!originalModule.webpackPolyfill) {
                    var module = Object.create(originalModule);
                    // module.parent = undefined by default
                    if (!module.children) module.children = [];
                    Object.defineProperty(module, "loaded", {
                        enumerable: true,
                        get: function () {
                            return module.l;
                        }
                    });
                    Object.defineProperty(module, "id", {
                        enumerable: true,
                        get: function () {
                            return module.i;
                        }
                    });
                    Object.defineProperty(module, "exports", {
                        enumerable: true
                    });
                    module.webpackPolyfill = 1;
                }
                return module;
            };


            /***/
        })

    /******/
});