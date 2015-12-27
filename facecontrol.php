<?php
/**
 * @package      ITPrism
 * @subpackage   Plugins
 * @author       Todor Iliev
 * @copyright    Copyright (C) 2016 Todor Iliev <todor@itprism.com>. All rights reserved.
 * @license      http://www.gnu.org/licenses/gpl-3.0.en.html GNU/GPLv3
 */

// No direct access
defined('_JEXEC') or die;

/**
 * This plugin controls users login.
 *
 * @package        ITPrism
 * @subpackage     Plugins
 */
class PlgUserFacecontrol extends JPlugin
{
    /**
     * This method will be executed before the user authentication.
     *
     * @param   array $credentials
     * @param   array $options Array of extra options
     *
     * @return  bool
     */
    public function onUserBeforeAuthenticate($credentials, &$options)
    {
        $app = JFactory::getApplication();
        /** @var $app JApplicationSite */

        if ($app->isAdmin()) {
            return null;
        }

        $doc = JFactory::getDocument();
        /**  @var $doc JDocumentHtml */

        // Check document type
        $docType = $doc->getType();
        if (strcmp('html', $docType) !== 0) {
            return null;
        }

        $ipAddressesFile = JPath::clean(__DIR__ . '/files/ip.txt');
        $content         = $this->getContent($ipAddressesFile);

        $isBruteForceAttack = false;
        $isMailSent         = false;
        $ip                 = $this->getIp($app);

        foreach ($content as $key => $userData) {
            if (strcmp($userData['ip'], $ip) === 0 and ($userData['tries'] >= 10)) {
                $today = new JDate;

                $bannedTo = new JDate($userData['date']);
                $bannedTo->add(new DateInterval('P' . (int)$this->params->get('ban_period', 7) . 'D'));

                if ($today <= $bannedTo) {
                    $isBruteForceAttack         = true;
                    $isMailSent                 = (bool)$content[$key]['mail_sent'];
                    $content[$key]['mail_sent'] = 1;
                }

                break;
            }
        }

        if ($isBruteForceAttack) {
            // Send notification mail to the administrator.
            if ($this->params->get('send_email_brute_force', 0) and !$isMailSent) {
                $this->loadLanguage();
                $uri = JUri::getInstance();

                $senderId = $this->params->get('sender_id');
                $sender   = JFactory::getUser($senderId);
                $subject  = JText::_('PLG_USER_FACECONTROL_BRUTE_FORCE_ATTACK_SUBJECT');
                $body     = JText::sprintf('PLG_USER_FACECONTROL_BRUTE_FORCE_BODY_S', $ip, $uri->toString(array('scheme', 'host', 'port')));

                $mailer = JFactory::getMailer();
                $return = $mailer->sendMail($sender->get('email'), $sender->get('name'), $app->get('mailfrom'), $subject, $body);

                // Check for an error.
                if ($return !== true) {
                    JLog::add(JText::sprintf('PLG_USER_FACECONTROL_MAIL_ERROR_S', $mailer->ErrorInfo));
                }

                // Write the content.
                $buffer = json_encode($content);
                JFile::write($ipAddressesFile, $buffer);
            }

            $options['silent'] = true;

            return false;
        }

        return true;
    }

    /**
     * This method will be called if the login process fails
     *
     * @param   array $response
     *
     * @return  bool
     */
    public function onUserLoginFailure($response)
    {
        $app = JFactory::getApplication();
        /** @var $app JApplicationSite */

        if ($app->isAdmin()) {
            return;
        }

        $doc = JFactory::getDocument();
        /**  @var $doc JDocumentHtml */

        // Check document type
        $docType = $doc->getType();
        if (strcmp('html', $docType) !== 0) {
            return;
        }

        $ipAddressesFile = JPath::clean(__DIR__ . '/files/ip.txt');
        $content         = $this->getContent($ipAddressesFile);

        $recordExists = false;
        $ip           = $this->getIp($app);

        $today          = new JDate();
        $todayFormatted = $today->format('Y-m-d');

        foreach ($content as $key => $userData) {
            if (strcmp($userData['ip'], $ip) === 0) {
                if ($userData['date'] === $todayFormatted) {
                    $content[$key]['tries']++;
                } else { // Restart tries.
                    $content[$key]['date']      = $todayFormatted;
                    $content[$key]['tries']     = 1;
                    $content[$key]['mail_sent'] = 0;
                }

                $recordExists = true;
                break;
            }
        }

        if (!$recordExists) {
            $content[] = array(
                'ip'        => $ip,
                'date'      => $todayFormatted,
                'tries'     => 1,
                'mail_sent' => 0
            );
        }

        // Write the content.
        $buffer = json_encode($content);
        JFile::write($ipAddressesFile, $buffer);
    }

    /**
     * This method should handle whenever you would like to authorize a user by additional criteria.
     *
     * @param   stdClass $response
     * @param   array    $options Array of extra options
     *
     * @return  bool
     */
    public function onUserAuthorisation($response, &$options)
    {
        $app = JFactory::getApplication();
        /** @var $app JApplicationSite */

        if ($app->isAdmin()) {
            return null;
        }

        $doc = JFactory::getDocument();
        /**  @var $doc JDocumentHtml */

        // Check document type
        $docType = $doc->getType();
        if (strcmp('html', $docType) !== 0) {
            return null;
        }

        $whiteList = $this->params->get('ip');
        $whiteList = preg_replace('/\s+/', '', $whiteList);
        $whiteList = explode(',', $whiteList);

        $whiteList = array_filter($whiteList, 'JString::trim');

        $ip = $this->getIp($app);

        if (count($whiteList) > 0 and !in_array($ip, $whiteList, true)) {
            $response->status  = JAuthentication::STATUS_DENIED;
            $options['silent'] = true;

            return $response;
        }

        // Send notification mail to the administrator,
        // if someone has logged in on the website.
        if ($this->params->get('send_email_login', 0)) {
            $this->loadLanguage();
            $uri = JUri::getInstance();

            $senderId = $this->params->get('sender_id');
            $sender   = JFactory::getUser($senderId);
            $subject  = JText::_('PLG_USER_FACECONTROL_SUBJECT');
            $body     = JText::sprintf('PLG_USER_FACECONTROL_BODY_S', $response->fullname, $uri->toString(array('scheme', 'host', 'port')));

            $mailer = JFactory::getMailer();
            $return = $mailer->sendMail($sender->get('email'), $sender->get('name'), $app->get('mailfrom'), $subject, $body);

            // Check for an error.
            if ($return !== true) {
                JLog::add(JText::sprintf('PLG_USER_FACECONTROL_MAIL_ERROR_S', $mailer->ErrorInfo));
            }
        }

        return $response;
    }

    protected function getIp($app)
    {
        if ($app->input->server->get('HTTP_CLIENT_IP')) {
            $ip = $app->input->server->get('HTTP_CLIENT_IP');
        } elseif ($app->input->server->get('HTTP_X_FORWARDED_FOR')) {
            $ip = $app->input->server->get('HTTP_X_FORWARDED_FOR');
        } else {
            $ip = $app->input->server->get('REMOTE_ADDR');
        }

        $ip = long2ip(ip2long($ip));

        return $ip;
    }

    protected function getContent($ipAddressesFile)
    {
        jimport('joomla.filesystem.file');

        if (!JFile::exists($ipAddressesFile)) {
            $buffer = '';
            JFile::write($ipAddressesFile, $buffer);

            $htaccessFile = JPath::clean(__DIR__ . '/files/.htaccess');
            if (!JFile::exists($htaccessFile)) {
                $buffer = 'Deny from all';
                JFile::write($htaccessFile, $buffer);
            }
        }

        $content = file_get_contents($ipAddressesFile);
        if (!$content) {
            $content = array();
        } else {
            $content = json_decode($content, true);

            // If the JSON is broken.
            if (!$content) {
                $content = array();
            }
        }

        return $content;
    }
}
