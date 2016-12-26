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

JLoader::registerNamespace('Prism', JPATH_LIBRARIES);

/**
 * This plugin controls users login.
 *
 * @package        ITPrism
 * @subpackage     Plugins
 */
class PlgUserFacecontrol extends JPlugin
{
    private $fileIpAddresses;
    private $filesFolder;
    
    /**
     * Constructor
     *
     * @param   stdClass &$subject   The object to observe
     * @param   array  $config     An optional associative array of configuration settings.
     *                             Recognized key values include 'name', 'group', 'params', 'language'
     *                             (this list is not meant to be comprehensive).
     *
     * @since   1.5
     *
     * @throws \UnexpectedValueException
     */
    public function __construct(&$subject, $config = array()) {
        parent::__construct($subject, $config);

        $this->filesFolder      = JPath::clean(__DIR__ . '/files', '/');
        $this->fileIpAddresses  = JPath::clean($this->filesFolder .'/ip.log', '/');
    }

    /**
     * This method will be called if the login process fails.
     *
     * @param   array $response
     *
     * @throws \UnexpectedValueException
     *
     * @return  null|bool
     */
    public function onUserLoginFailure($response)
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

        $content            = $this->getContent($this->fileIpAddresses);

        $isBruteForceAttack = false;
        $recordExists       = false;
        $ip                 = Prism\Utilities\NetworkHelper::getIpAddress();

        if ($ip !== '') {
            $today          = new JDate();
            $todayFormatted = $today->format('Y-m-d');

            foreach ($content as $key => $userData) {
                if (strcmp($userData['ip'], $ip) === 0) {
                    if ($userData['date'] === $todayFormatted) {
                        $content[$key]['attempts']++;
                    } else { // Restart attempts.
                        $content[$key]['date']     = $todayFormatted;
                        $content[$key]['attempts'] = 1;
                    }

                    $recordExists = true;

                    $isBruteForceAttack = $this->isBruteForceAttack($content[$key]);
                    break;
                }
            }

            if (!$recordExists) {
                $content[] = array(
                    'ip'       => $ip,
                    'date'     => $todayFormatted,
                    'attempts' => 1
                );
            }
        }

        // Send notification mail to the administrator.
        if ($isBruteForceAttack and $this->params->get('send_email_brute_force', 0)) {
            $this->loadLanguage();
            $uri = JUri::getInstance();

            $senderId = $this->params->get('sender_id');
            $sender   = JFactory::getUser($senderId);
            $subject  = JText::_('PLG_USER_FACECONTROL_BRUTE_FORCE_ATTACK_SUBJECT');
            $body     = JText::sprintf('PLG_USER_FACECONTROL_BRUTE_FORCE_BODY_S', $ip, $uri->toString(array('scheme', 'host', 'port')));

            $mailer   = JFactory::getMailer();
            $return   = $mailer->sendMail($sender->get('email'), $sender->get('name'), $app->get('mailfrom'), $subject, $body);

            // Check for an error.
            if ($return !== true) {
                JLog::add(JText::sprintf('PLG_USER_FACECONTROL_MAIL_ERROR_S', $mailer->ErrorInfo));
            }
        }

        // Store the content.
        $buffer = json_encode($content);
        JFile::write($this->fileIpAddresses, $buffer);
    }

    /**
     * This method should handle whenever you would like to authorize a user by additional criteria.
     *
     * @param   JAuthenticationResponse $user
     * @param   array    $options Array of extra options
     *
     * @return  null|JAuthenticationResponse
     */
    public function onUserAuthorisation($user, $options)
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

        // Check if the IP address exists in the "White List".
        $whiteList  = $this->getWhiteList();
        $ip         = Prism\Utilities\NetworkHelper::getIpAddress();

        if (count($whiteList) > 0 and !in_array($ip, $whiteList, true)) {
            $user->status  = JAuthentication::STATUS_DENIED;
            return $user;
        }

        // Send notification mail to the administrator,
        // if someone has logged in on the website.
        if ($this->params->get('send_email_login', 0)) {
            $this->loadLanguage();
            $uri = JUri::getInstance();

            $senderId = $this->params->get('sender_id');
            $sender   = JFactory::getUser($senderId);
            $subject  = JText::_('PLG_USER_FACECONTROL_SUBJECT');
            $body     = JText::sprintf('PLG_USER_FACECONTROL_BODY_S', $user->fullname, $uri->toString(array('scheme', 'host', 'port')));

            $mailer = JFactory::getMailer();
            $return = $mailer->sendMail($sender->get('email'), $sender->get('name'), $app->get('mailfrom'), $subject, $body);

            // Check for an error.
            if ($return !== true) {
                JLog::add(JText::sprintf('PLG_USER_FACECONTROL_MAIL_ERROR_S', $mailer->ErrorInfo));
            }
        }

        return null;
    }

    protected function isBruteForceAttack($userData)
    {
        if ((int)$userData['attempts'] >= (int)$this->params->get('allowed_failures', 10)) {
            $today    = new JDate;

            $bannedTo = new JDate($userData['date']);
            $bannedTo->add(new DateInterval('P' . (int)$this->params->get('ban_period', 7) . 'D'));

            if ($today <= $bannedTo) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param $ipAddressesFile
     *
     * @throws \UnexpectedValueException
     * @return array
     */
    protected function getContent($ipAddressesFile)
    {
        jimport('joomla.filesystem.file');

        if (!JFile::exists($ipAddressesFile)) {
            $buffer = '';
            JFile::write($ipAddressesFile, $buffer);

            $htaccessFile = JPath::clean($this->filesFolder.'/.htaccess', '/');
            if (!JFile::exists($htaccessFile)) {
                $buffer = 'Deny from all';
                JFile::write($htaccessFile, $buffer);
            }
        }

        $content = file_get_contents($ipAddressesFile);
        if (!$content) {
            $content = array();
        } else {
            $content = (array)json_decode($content, true);
        }

        return $content;
    }

    protected function getWhiteList()
    {
        $whiteList = $this->params->get('ip');
        $whiteList = preg_replace('/\s+/', '', $whiteList);
        $whiteList = explode(',', $whiteList);

        $whiteList = array_filter($whiteList, 'JString::trim');

        return $whiteList;
    }
}
